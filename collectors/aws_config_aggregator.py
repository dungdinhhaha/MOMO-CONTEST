"""Read-only, multi-account AWS inventory collector for PathGuard.

Requires an already configured AWS Config organization aggregator. It does not
create resources, assume roles in member accounts, or change AWS configuration.
"""

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

try:
    from .aws_connection import create_aws_session, verify_caller_identity
except ImportError:
    from aws_connection import create_aws_session, verify_caller_identity


RESOURCE_TYPES = (
    "AWS::EC2::VPC",
    "AWS::EC2::Subnet",
    "AWS::EC2::RouteTable",
    "AWS::EC2::SecurityGroup",
    "AWS::EC2::NetworkInterface",
    "AWS::EC2::Instance",
    "AWS::EC2::NetworkAcl",
    "AWS::EC2::TransitGateway",
    "AWS::EC2::TransitGatewayAttachment",
    "AWS::EC2::TransitGatewayRouteTable",
    "AWS::EC2::VPCEndpoint",
    "AWS::EC2::VPCPeeringConnection",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::ECS::Cluster",
    "AWS::ECS::Service",
    "AWS::EKS::Cluster",
    "AWS::Config::ConfigurationRecorder",
)
BATCH_SIZE = 100


class AwsConfigAggregatorCollector:
    """Read AWS Config's central, read-only view across accounts and Regions."""

    def __init__(self, aggregator, region, profile=None, client=None, role_arn=None,
                 external_id=None, role_session_name="PathGuardReadOnly", connection_id=None,
                 expected_account_id=None):
        self.profile = profile
        if connection_id is not None and not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", connection_id):
            raise ValueError("Connection ID must be 1-128 safe identifier characters")
        if expected_account_id is not None and client is not None:
            raise ValueError("Expected account validation requires a real AWS session")
        self.connection_id = connection_id
        self.expected_account_id = expected_account_id
        self.session = None
        self.caller_identity = None
        if client is None:
            from botocore.config import Config

            session = create_aws_session(region, profile, role_arn, external_id,
                                         role_session_name)
            self.session = session
            self.caller_identity = verify_caller_identity(session, expected_account_id)
            client = session.client("config", config=Config(
                connect_timeout=5, read_timeout=30,
                retries={"mode": "standard", "total_max_attempts": 3},
                max_pool_connections=20,
            ))
        self.client = client
        self.aggregator = aggregator
        self.region = region

    def collect(self, resource_types=RESOURCE_TYPES):
        from botocore.exceptions import BotoCoreError, ClientError
        stamp = datetime.now(timezone.utc).isoformat()
        aggregator = self.client.describe_configuration_aggregators(
            ConfigurationAggregatorNames=[self.aggregator]
        ).get("ConfigurationAggregators", [])
        if len(aggregator) != 1:
            raise ValueError(f"AWS Config aggregator not found or ambiguous: {self.aggregator}")

        status_pages = self.client.get_paginator("describe_configuration_aggregator_sources_status")
        statuses = []
        for page in status_pages.paginate(ConfigurationAggregatorName=self.aggregator):
            statuses.extend(page.get("AggregatedSourceStatusList", []))

        resources = []
        errors = []
        for resource_type in resource_types:
            identifiers = []
            try:
                pages = self.client.get_paginator("list_aggregate_discovered_resources")
                for page in pages.paginate(ConfigurationAggregatorName=self.aggregator,
                                           ResourceType=resource_type, Limit=100):
                    identifiers.extend(page.get("ResourceIdentifiers", []))
            except (BotoCoreError, ClientError) as error:
                errors.append({"resource_type": resource_type,
                               "error_type": type(error).__name__,
                               "detail": str(error)[:500]})
                continue

            for offset in range(0, len(identifiers), BATCH_SIZE):
                batch = identifiers[offset:offset + BATCH_SIZE]
                response = self.client.batch_get_aggregate_resource_config(
                    ConfigurationAggregatorName=self.aggregator,
                    ResourceIdentifiers=batch,
                )
                for item in response.get("BaseConfigurationItems", []):
                    config = item.get("configuration")
                    if isinstance(config, str):
                        try:
                            config = json.loads(config)
                        except json.JSONDecodeError:
                            config = {"unparsed_configuration": config[:2000]}
                    relationships = item.get("relationships", []) or []
                    resources.append({
                        "id": ":".join((item.get("accountId", "unknown"),
                                        item.get("awsRegion", "unknown"),
                                        item.get("resourceType", resource_type),
                                        item.get("resourceId", "unknown"))),
                        "source_connection_id": self.connection_id,
                        "account_id": item.get("accountId"),
                        "region": item.get("awsRegion"),
                        "type": item.get("resourceType", resource_type),
                        "resource_id": item.get("resourceId"),
                        "arn": item.get("arn"),
                        "name": item.get("resourceName"),
                        "tags": item.get("tags") or {},
                        "configuration_item_status": item.get("configurationItemStatus"),
                        "configuration_state_id": item.get("configurationStateId"),
                        "configuration": config if isinstance(config, dict) else {},
                        "relationships": [{
                            "resource_type": link.get("resourceType"),
                            "resource_id": link.get("resourceId"),
                            "name": link.get("name"),
                        } for link in relationships],
                    })

        coverage = self._normalize_coverage(statuses)
        healthy = bool(coverage) and all(item["status"] == "SUCCEEDED" for item in coverage)
        recording_coverage = self._recording_coverage(resources, coverage)
        scope_inventory, scope_errors = self._expected_scope()
        return {
            "source": "aws-config-aggregator",
            "source_connection_id": self.connection_id,
            "caller_identity": self.caller_identity,
            "tenant_authority": "must_be_bound_by_authenticated_server_connection_registry",
            "aggregator": self.aggregator,
            "aggregator_region": self.region,
            "collected_at": stamp,
            "read_only": True,
            "coverage_status": "partial_or_unverified",
            "aggregator_source_sync_status": "succeeded" if healthy else "partial_or_failed",
            "expected_scope": {**scope_inventory,
                "denominator": len(scope_inventory.get("active_accounts", [])) * len(scope_inventory.get("enabled_regions", [])) * len(resource_types),
                "resource_types": list(resource_types), "collection_errors": scope_errors},
            "source_coverage": coverage,
            "recording_coverage": recording_coverage,
            "resource_types_requested": list(resource_types),
            "resource_count": len(resources),
            "resources": resources,
            "collection_errors": errors,
            "limitations": [
                "Requires AWS Config recorder enabled in each account and Region in scope.",
                "Aggregator status only reports sources AWS Config knows about; verify account and Region inventory separately.",
                "Configuration inventory is not network traffic, application dependency, identity activity, or business-purpose evidence.",
            ],
        }

    def collect_to(self, resource_path, manifest_path, resource_types=RESOURCE_TYPES):
        """Stream resources as JSONL so large organizations are not held in RAM."""
        from botocore.exceptions import BotoCoreError, ClientError
        stamp = datetime.now(timezone.utc).isoformat()
        aggregator = self.client.describe_configuration_aggregators(
            ConfigurationAggregatorNames=[self.aggregator]
        ).get("ConfigurationAggregators", [])
        if len(aggregator) != 1:
            raise ValueError(f"AWS Config aggregator not found or ambiguous: {self.aggregator}")
        status_pages = self.client.get_paginator("describe_configuration_aggregator_sources_status")
        statuses = []
        for page in status_pages.paginate(ConfigurationAggregatorName=self.aggregator):
            statuses.extend(page.get("AggregatedSourceStatusList", []))

        resource_path = Path(resource_path)
        manifest_path = Path(manifest_path)
        resource_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        errors = []
        unprocessed_count = 0
        unprocessed_ids = []
        count = 0
        recorder_accounts = set()
        requested_cells = {}
        with resource_path.open("w", encoding="utf-8", newline="\n") as output:
            for resource_type in resource_types:
                try:
                    identifiers = []
                    pages = self.client.get_paginator("list_aggregate_discovered_resources")
                    for page in pages.paginate(ConfigurationAggregatorName=self.aggregator,
                                               ResourceType=resource_type, Limit=100):
                        identifiers.extend(page.get("ResourceIdentifiers", []))
                    for identifier in identifiers:
                        key = (identifier.get("SourceAccountId"), identifier.get("SourceRegion"), resource_type)
                        cell = requested_cells.setdefault(key, {"scope": "aws", "account_id": key[0], "region": key[1],
                            "resource_type": resource_type, "listed_count": 0, "decoded_count": 0,
                            "configured": "unknown", "delivered": "unknown", "decoded": "unknown", "validated": "unknown"})
                        cell["listed_count"] += 1
                        cell["delivered"] = "delivered"
                    for offset in range(0, len(identifiers), BATCH_SIZE):
                        batch = identifiers[offset:offset + BATCH_SIZE]
                        response = self.client.batch_get_aggregate_resource_config(
                            ConfigurationAggregatorName=self.aggregator, ResourceIdentifiers=batch)
                        pending = response.get("UnprocessedResourceIdentifiers", [])
                        unprocessed_count += len(pending)
                        unprocessed_ids.extend(pending)
                        for item in response.get("BaseConfigurationItems", []):
                            normalized = self._normalize_item(item, resource_type)
                            normalized["source_connection_id"] = self.connection_id
                            key = (normalized["account_id"], normalized["region"], normalized["type"])
                            cell = requested_cells.get(key)
                            if cell:
                                cell["decoded_count"] += 1
                                cell["decoded"] = "decoded"
                                cell["validated"] = "validated" if isinstance(item.get("configuration"), (dict, str)) else "unknown"
                            if normalized["type"] == "AWS::Config::ConfigurationRecorder" and normalized["account_id"]:
                                recorder_accounts.add(normalized["account_id"])
                            output.write(json.dumps(normalized, ensure_ascii=False, separators=(",", ":")) + "\n")
                            count += 1
                except (BotoCoreError, ClientError) as error:
                    errors.append({"resource_type": resource_type,
                                   "error_type": type(error).__name__, "detail": str(error)[:500]})

        coverage = self._normalize_coverage(statuses)
        scope_inventory, scope_errors = self._expected_scope()
        errors.extend(scope_errors)
        healthy = bool(coverage) and all(item["status"] == "SUCCEEDED" for item in coverage)
        recording_coverage = self._recording_coverage(
            [{"account_id": account_id, "type": "AWS::Config::ConfigurationRecorder"}
             for account_id in recorder_accounts], coverage)
        source_by_cell = {(item.get("account_id"), item.get("region")): item for item in coverage
                          if item.get("account_id") and item.get("region")}
        expected_cells = []
        enabled_accounts = scope_inventory.get("active_accounts", [])
        enabled_regions = scope_inventory.get("enabled_regions", [])
        for account_id in enabled_accounts:
            for aws_region in enabled_regions:
                source = source_by_cell.get((account_id, aws_region))
                for resource_type in resource_types:
                    observed = requested_cells.get((account_id, aws_region, resource_type))
                    expected_cells.append({"scope": "aws", "account_id": account_id, "region": aws_region,
                        "resource_type": resource_type,
                        "configured": "unknown", "delivered": "unknown", "decoded": "unknown", "validated": "unknown",
                        "source_status": source.get("status") if source else None,
                        "source_last_update": source.get("last_update") if source else None,
                        "source_error": source.get("error_message") if source else None,
                        "listed_count": observed.get("listed_count", 0) if observed else 0,
                        "decoded_count": observed.get("decoded_count", 0) if observed else 0,
                        "status": "unknown" if not source else ("partial" if source.get("status") != "SUCCEEDED" else "delivered")})
        for cell in expected_cells:
            observed = requested_cells.get((cell["account_id"], cell["region"], cell["resource_type"]))
            if observed:
                cell.update({key: observed[key] for key in ("configured", "delivered", "decoded", "validated", "listed_count", "decoded_count")})
            cell["status"] = ("validated" if cell["validated"] == "validated" else
                               "partial" if cell["source_status"] else "unknown")
        manifest = {
            "source": "aws-config-aggregator", "aggregator": self.aggregator,
            "aggregator_region": self.region, "collected_at": stamp, "read_only": True,
            "source_connection_id": self.connection_id,
            "caller_identity": self.caller_identity,
            "tenant_authority": "must_be_bound_by_authenticated_server_connection_registry",
            "coverage_status": "partial_or_unverified",
            "source_coverage": coverage, "resource_types_requested": list(resource_types),
            "expected_scope": {**scope_inventory, "denominator": len(expected_cells), "cells": expected_cells,
                               "gaps": [cell for cell in expected_cells if cell["status"] != "validated"]},
            "recording_coverage": recording_coverage,
            "resource_count": count, "resources_jsonl": str(resource_path),
            "unprocessed_resource_count": unprocessed_count, "unprocessed_resource_identifiers": unprocessed_ids,
            "collection_errors": errors,
            "freshness": {"collected_at": stamp,
                          "oldest_source_update": min((x["last_update"] for x in coverage if x.get("last_update")), default=None),
                          "newest_source_update": max((x["last_update"] for x in coverage if x.get("last_update")), default=None)},
            "limitations": [
                "Requires AWS Config recorder in every intended account and Region.",
                "Reported aggregator sources do not prove all Organization accounts/Regions are covered.",
                "Recorder inventory is evidence of observed recorder resources, not proof that every resource type is recorded.",
                "Inventory is not traffic, application dependency, identity activity, or business-purpose evidence.",
            ],
        }
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return manifest

    def _expected_scope(self):
        """Read the AWS Organizations account and enabled Region denominator."""
        from botocore.exceptions import BotoCoreError, ClientError
        errors = []
        try:
            from botocore.config import Config
            session = self.session
            if session is None:
                return {"organization_account_status": "unknown", "active_accounts": [],
                        "region_status": "unknown", "enabled_regions": []}, [
                            {"scope": "organization_region_denominator",
                             "error_type": "SessionUnavailable",
                             "detail": "AWS session was not retained by this collector"}]
            organization = session.client("organizations", region_name="us-east-1", config=Config(connect_timeout=5, read_timeout=15))
            accounts = [account["Id"] for page in organization.get_paginator("list_accounts").paginate()
                        for account in page.get("Accounts", []) if account.get("Status") == "ACTIVE"]
            ec2 = session.client("ec2", region_name=self.region, config=Config(connect_timeout=5, read_timeout=15))
            regions = [item["RegionName"] for item in ec2.describe_regions(AllRegions=False).get("Regions", [])]
            return {"organization_account_status": "read", "active_accounts": sorted(accounts),
                    "region_status": "read", "enabled_regions": sorted(regions)}, errors
        except (BotoCoreError, ClientError, Exception) as error:
            errors.append({"scope": "organization_region_denominator", "error_type": type(error).__name__,
                           "detail": str(error)[:500]})
            return {"organization_account_status": "unknown", "active_accounts": [],
                    "region_status": "unknown", "enabled_regions": []}, errors

    @staticmethod
    def _normalize_item(item, fallback_type):
        config = item.get("configuration")
        if isinstance(config, str):
            try:
                config = json.loads(config)
            except json.JSONDecodeError:
                config = {"unparsed_configuration": config[:2000]}
        return {
            "id": ":".join((item.get("accountId", "unknown"), item.get("awsRegion", "unknown"),
                            item.get("resourceType", fallback_type), item.get("resourceId", "unknown"))),
            "account_id": item.get("accountId"), "region": item.get("awsRegion"),
            "type": item.get("resourceType", fallback_type), "resource_id": item.get("resourceId"),
            "arn": item.get("arn"), "name": item.get("resourceName"),
            "tags": item.get("tags") or {},
            "configuration_item_status": item.get("configurationItemStatus"),
            "configuration_state_id": item.get("configurationStateId"),
            "configuration": config if isinstance(config, dict) else {},
            "relationships": [{"resource_type": link.get("resourceType"),
                               "resource_id": link.get("resourceId"), "name": link.get("name")}
                              for link in (item.get("relationships", []) or [])],
        }

    @staticmethod
    def _normalize_coverage(statuses):
        coverage = []
        for status in statuses:
            source_type = status.get("SourceType")
            source_id = status.get("SourceId")
            coverage.append({
                "account_id": status.get("AwsAccountId") or (source_id if source_type == "ACCOUNT" else None),
                "region": status.get("AwsRegion"), "source_type": source_type,
                "status": status.get("LastUpdateStatus"),
                "last_update": status.get("LastUpdateTime").isoformat() if status.get("LastUpdateTime") else None,
                "error_code": status.get("LastErrorCode"), "error_message": status.get("LastErrorMessage"),
            })
        return coverage

    @staticmethod
    def _recording_coverage(resources, coverage):
        observed = sorted({item.get("account_id") for item in resources
                           if item.get("type") == "AWS::Config::ConfigurationRecorder" and item.get("account_id")})
        source_accounts = sorted({item.get("account_id") for item in coverage
                                  if item.get("source_type") == "ACCOUNT" and item.get("account_id")})
        return {
            "observed_recorder_account_ids": observed,
            "source_account_ids_without_observed_recorder": sorted(set(source_accounts) - set(observed)),
            "interpretation": "No observed recorder is a coverage gap to investigate; it does not prove the account has no recorder.",
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aggregator", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile")
    parser.add_argument("--role-arn", help="Customer IAM role to assume for read-only collection")
    parser.add_argument("--external-id", help="Required with --role-arn; bind the customer connection")
    parser.add_argument("--role-session-name", default="PathGuardReadOnly")
    parser.add_argument("--connection-id", help="PathGuard connection reference; metadata only until server-bound")
    parser.add_argument("--expected-account-id", help="Require the STS caller identity to match this 12-digit account ID")
    parser.add_argument("--output", type=Path, required=True, help="JSONL resource output path")
    args = parser.parse_args()
    manifest_path = args.output.with_suffix(args.output.suffix + ".manifest.json")
    report = AwsConfigAggregatorCollector(
        args.aggregator, args.region, args.profile, role_arn=args.role_arn,
        external_id=args.external_id, role_session_name=args.role_session_name,
        connection_id=args.connection_id, expected_account_id=args.expected_account_id,
    ).collect_to(args.output, manifest_path)
    print(json.dumps({"output": str(args.output), "manifest": str(manifest_path),
                      "resources": report["resource_count"], "coverage_status": report["coverage_status"],
                      "errors": len(report["collection_errors"])}, ensure_ascii=False))


if __name__ == "__main__":
    main()
