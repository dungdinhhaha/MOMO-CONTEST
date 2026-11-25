"""Collect a read-only AWS Config organization snapshot and ingest it into PathGuard."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from .aws_config_aggregator import AwsConfigAggregatorCollector
except ImportError:
    from aws_config_aggregator import AwsConfigAggregatorCollector


SCHEMA_VERSION = "pathguard.evidence-bundle.v1"
MAX_BUNDLE_BYTES = 2 * 1024 * 1024
MAX_RECORDS = 5_000
SECRET_FIELD = re.compile(
    r"(?i).*(password|passwd|secret|credential|authorization|api.?key|access.?key|private.?key|(^|_)token($|_)).*"
)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def backend_request(base_url: str, path: str, body: dict, token: str | None = None) -> dict:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"PathGuardConnector {token}"
    request = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
            raw = response.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024:
            raise ValueError("PathGuard response exceeded 64 KiB")
        decoded = json.loads(raw)
        if not isinstance(decoded, dict):
            raise ValueError("PathGuard response was not a JSON object")
        return decoded
    except urllib.error.HTTPError as error:
        raise ValueError(f"PathGuard returned HTTP {error.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ValueError(f"PathGuard connection failed ({type(error).__name__})") from None


def save_token(path: Path, token: str) -> None:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("Connector credential file must not be a symlink")
    fd, temporary_name = tempfile.mkstemp(prefix=".pathguard-token-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(token + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.chmod(temporary_name, 0o600)
        except OSError:
            pass
        os.replace(temporary_name, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def connector_token(base_url: str, connection_id: str, credential_file: Path,
                    expected_type: str = "AWS") -> str:
    if credential_file.exists():
        if credential_file.is_symlink():
            raise ValueError("Connector credential file must not be a symlink")
        token = credential_file.read_text(encoding="utf-8").strip()
        if not token.startswith("pgc_"):
            raise ValueError("Stored PathGuard connector credential is invalid")
        return token

    enrollment = os.environ.pop("PATHGUARD_ENROLLMENT_TOKEN", "").strip()
    if not enrollment.startswith("pge_"):
        raise ValueError("Set PATHGUARD_ENROLLMENT_TOKEN from a one-time connector enrollment")
    issued = backend_request(base_url, "/api/v1/connectors/enroll", {"enrollmentToken": enrollment})
    token = issued.get("connectorToken")
    if (not isinstance(token, str) or not token.startswith("pgc_")
            or issued.get("connectorType") != expected_type
            or issued.get("connectionId") != connection_id):
        raise ValueError("PathGuard enrollment does not match this connection and connector type")
    save_token(credential_file, token)
    return token


def strip_sensitive_fields(value, redactions: list[str], path: str = "payload"):
    if isinstance(value, dict):
        cleaned = {}
        for key, child in value.items():
            if SECRET_FIELD.fullmatch(str(key)):
                redactions.append(f"{path}.{key}")
                continue
            cleaned[key] = strip_sensitive_fields(child, redactions, f"{path}.{key}")
        return cleaned
    if isinstance(value, list):
        return [strip_sensitive_fields(child, redactions, f"{path}[{index}]")
                for index, child in enumerate(value)]
    return value


def build_bundle(resource_path: Path, manifest: dict, connection_id: str) -> dict:
    collected_at = datetime.now(timezone.utc)
    timestamp = collected_at.isoformat(timespec="seconds").replace("+00:00", "Z")
    records = []
    redactions: list[str] = []
    with resource_path.open("r", encoding="utf-8") as source:
        for line in source:
            resource = json.loads(line)
            account = resource.get("account_id") or "unknown"
            region = resource.get("region") or "unknown"
            resource_type = resource.get("type") or "unknown"
            resource_id = resource.get("resource_id") or "unknown"
            resource_key = f"aws/{account}/{region}/{resource_type}/{resource_id}"
            payload = strip_sensitive_fields(resource, redactions)
            canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            record_id = hashlib.sha256(f"{resource_key}\n{canonical}".encode("utf-8")).hexdigest()
            records.append({
                "id": f"aws-{record_id}",
                "evidence_type": "aws-config-resource",
                "resource_key": resource_key,
                "observed_at": timestamp,
                "payload": payload,
            })
            if len(records) > MAX_RECORDS - 1:
                raise ValueError(f"AWS aggregator inventory exceeds {MAX_RECORDS - 1} resource records")

    scope = manifest.get("expected_scope", {})
    coverage_payload = {
        "source": "aws-config-aggregator",
        "aggregator": manifest.get("aggregator"),
        "aggregator_region": manifest.get("aggregator_region"),
        "read_only": True,
        "coverage_status": manifest.get("coverage_status", "partial_or_unverified"),
        "source_coverage": manifest.get("source_coverage", []),
        "resource_types_requested": manifest.get("resource_types_requested", []),
        "active_accounts": scope.get("active_accounts", []),
        "enabled_regions": scope.get("enabled_regions", []),
        "denominator": scope.get("denominator"),
        "recording_coverage": manifest.get("recording_coverage", {}),
        "unprocessed_resource_count": manifest.get("unprocessed_resource_count", 0),
        "collection_errors": manifest.get("collection_errors", []),
        "limitations": manifest.get("limitations", []),
        "redacted_sensitive_fields": len(redactions),
    }
    coverage_key = f"aws/{connection_id}/coverage/{timestamp}"
    records.append({
        "id": "aws-coverage-" + hashlib.sha256(coverage_key.encode("utf-8")).hexdigest(),
        "evidence_type": "aws-config-coverage",
        "resource_key": coverage_key,
        "observed_at": timestamp,
        "payload": coverage_payload,
    })

    bundle = {
        "schema_version": SCHEMA_VERSION,
        "source_type": "AWS",
        "connection_id": connection_id,
        "collected_at": timestamp,
        "records": records,
        "coverage": {
            "status": "partial",
            "window_start": (collected_at - timedelta(seconds=1)).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "window_end": timestamp,
        },
    }
    encoded = json.dumps(bundle, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_BUNDLE_BYTES:
        raise ValueError(f"Evidence bundle is {len(encoded)} bytes; API limit is {MAX_BUNDLE_BYTES}")
    return bundle


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aggregator", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", help="AWS profile with read-only access to the Config aggregator")
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--connection-id", required=True)
    parser.add_argument("--backend-url", required=True)
    parser.add_argument("--credential-file", type=Path, required=True)
    args = parser.parse_args()

    try:
        collector = AwsConfigAggregatorCollector(
            args.aggregator, args.region, args.profile,
            connection_id=args.connection_id,
            expected_account_id=args.expected_account_id,
        )
        with tempfile.TemporaryDirectory(prefix="pathguard-aws-aggregator-") as temporary:
            output = Path(temporary) / "resources.jsonl"
            manifest_path = Path(temporary) / "coverage.manifest.json"
            manifest = collector.collect_to(output, manifest_path)
            bundle = build_bundle(output, manifest, args.connection_id)
            token = connector_token(args.backend_url, args.connection_id, args.credential_file)
            response = backend_request(args.backend_url, "/api/v1/evidence/bundles", bundle, token)
            if response.get("recordCount") != len(bundle["records"]):
                raise ValueError("PathGuard did not confirm every evidence record")
        print(json.dumps({
            "status": "uploaded",
            "connection_id": args.connection_id,
            "aggregator": args.aggregator,
            "aws_resource_records": len(bundle["records"]) - 1,
            "coverage_records": 1,
            "bundle_id": response.get("bundleId"),
            "duplicate": response.get("duplicate"),
            "record_count": response.get("recordCount"),
            "aggregator_coverage": manifest.get("coverage_status"),
            "collection_errors": len(manifest.get("collection_errors", [])),
            "unprocessed_resource_count": manifest.get("unprocessed_resource_count", 0),
        }, ensure_ascii=False))
        return 0
    except Exception as error:
        print(f"AWS aggregator upload failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
