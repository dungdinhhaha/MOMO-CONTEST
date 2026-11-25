# AWS connection and network inventory

PathGuard connects to one AWS account and Region at a time using STS AssumeRole. It uses the customer's existing AWS Config recorder to collect the current network inventory; it does not create or change AWS resources.

## Flow

1. A tenant administrator calls `POST /api/v1/aws/connections/prepare` with `{"connectionId":"aws-lab"}`.
2. PathGuard returns a tenant-bound `externalId`. Add it to the target role trust policy.
3. Call `POST /api/v1/aws/connections/test`:

   ```json
   {
     "connectionId": "aws-lab",
     "roleArn": "arn:aws:iam::123456789012:role/PathGuardNetworkReadOnly",
     "expectedAccountId": "123456789012",
     "region": "ap-southeast-2"
   }
   ```

4. PathGuard assumes the role, verifies the account, collects AWS Config network resources and their current configuration, reads Flow Log definitions, queries up to 90 days of selected CloudTrail changes, reads up to 7 days of records from the configured CloudWatch Logs/S3 Flow Log destinations, and persists a tenant-scoped snapshot.
5. Read the saved snapshot with `GET /api/v1/aws/connections/{connectionId}/inventory`.

The test response reports identity, Config reachability, collected resource, CloudTrail event and Flow Log record counts, coverage (`COMPLETE`, `PARTIAL`, `UNKNOWN`), missing resource types, warnings and snapshot ID. `connectionReady` means that the role was verified and at least one resource was collected; it does not mean that every resource type or every log has been collected.

## Collected resource types

VPC, subnet, route table, security group, network ACL, network interface, EC2 instance, VPC Flow Log, VPC peering, Transit Gateway and its attachments/route tables, VPC endpoints, ELBv2 load balancers, ECS clusters/services and EKS clusters. AWS Config must already record a type for its resources to appear. Missing recorder coverage is returned explicitly.

The inventory records each resource's AWS account, Region, ID, name, configuration and selected references between network resources. Flow Log definitions are read directly from EC2 even if AWS Config does not record that resource type. Traffic records are normalized from existing CloudWatch Logs or S3 destinations. CloudTrail records are limited to mutating events from EC2, ELB, ECS/EKS, IAM, Config, CloudFormation, CodeDeploy, CodePipeline and CodeBuild. Each event contains its timestamp, actor, source, action and AWS resource references; raw event JSON is not stored.

The current collector is intentionally bounded: it reads recorded Config resource types with at most four workers. CloudTrail looks back 90 days, stores at most 200 qualifying events per event source, and reads at most 20 pages per source; reaching that page limit creates an explicit warning. CloudTrail lookup stays sequential to avoid exceeding its account-level API rate limit. Flow Logs look back 7 days, read at most 20 CloudWatch streams per group and at most 50 S3 objects, and store at most 20,000 normalized records across destinations. CloudWatch streams and the 50 newest S3 objects in the configured time window are read with at most five concurrent workers. `NODATA` and `SKIPDATA` Flow Log records are retained as explicit log-status evidence and are not successful connection observations. A record can therefore prove traffic was accepted/rejected only when `log-status=OK` and `action` is `ACCEPT` or `REJECT`.

Configuration-derived graph edges and observed Flow Log traffic are separate evidence. A Flow Log entry identifies an ENI/IP/protocol/port and time window; PathGuard does not yet resolve every ENI to an application microservice or correlate a connection to a deployment automatically. CI/CD events are only present when the account emitted matching CloudTrail events; current pipeline/project discovery and execution history are not yet collected directly.

## IAM and runtime identity

- PathGuard's runtime identity needs only `sts:AssumeRole` on the specific customer role ARNs it is allowed to connect to.
- The customer target role trust should name that runtime identity and require the exact `sts:ExternalId` returned by `/prepare`.
- The customer target role needs read-only AWS Config permissions for `DescribeConfigurationRecorders`, `DescribeConfigurationRecorderStatus`, `ListDiscoveredResources` and `BatchGetResourceConfig`, EC2 `DescribeFlowLogs`, CloudTrail `LookupEvents`, CloudWatch Logs `DescribeLogStreams`/`GetLogEvents`, and S3 `ListBucket`/`GetObject` scoped to the configured Flow Log destination prefix. The lab currently scopes S3 access to its existing `wallet/AWSLogs/.../vpcflowlogs/ap-southeast-2/` prefix.
- Do not pass long-lived AWS access keys or the broad operator role into the API container. Use a workload role in deployment; for a local lab, use short-lived credentials for a narrowly scoped runtime role.

The HMAC key `PATHGUARD_AWS_EXTERNAL_ID_HMAC_SECRET` must be a stable secret of at least 32 bytes and stored outside source control. Replacing it changes External IDs and invalidates existing role trust conditions.

## Scope and limitations

- This release collects one account and Region per request. Organization-wide, multi-account and multi-Region onboarding still needs an account/Region registry and fan-out orchestration.
- Collection reflects AWS Config's latest recorded state, not a live packet capture. AWS Config history starts only when recording is enabled.
- Current graph edges are not yet normalized from every configuration document. Flow Log traffic and selected CloudTrail change history are collected, but IAM effective permissions, direct pipeline execution history, on-prem logs, and complete service-to-service attribution are not part of this AWS snapshot.
- AWS operations in the connection test are read-only. It will not enable recorders, Flow Logs or alter routes/security groups.
