# AWS live collection test

## Result

PathGuard connected to the AWS sandbox through the tenant-scoped target role and persisted optimized snapshot `d455cc73-5022-4cdb-94cb-11a39da9f9eb` (collected at `2026-11-24T17:37:30Z`). The test was read-only. Terraform changed one inline policy on the PathGuard target role; it created and deleted no AWS resources.

| Evidence | Collected | What it proves |
|---|---:|---|
| AWS Config network inventory | 94 resources across 17 types | Current recorded network/resource configuration in one account and Region |
| Configuration reference edges | 293 | Relationships visible in the collected AWS configuration |
| CloudTrail changes | 56 events | Selected mutating events from EC2 (40), ELB (10), and Config (6) in the 90-day window |
| Flow Log records | 4,344 | Existing records read from CloudWatch Logs (4,219) and S3 (125) in the 7-day window |

Flow Log result breakdown for the latest run: 2,382 `REJECT/OK`, 1,506 `NODATA`, and 456 `SKIPDATA`; this run observed no `ACCEPT/OK` records. Only `ACCEPT` or `REJECT` with `log-status=OK` is treated as an observed network decision; `NODATA` and `SKIPDATA` are retained as evidence of missing/empty data, not as successful connections.

Direct read-only checks of CodePipeline and CodeBuild returned empty pipeline and project lists in this sandbox. CloudTrail had API query events for those services, but there was no deployment pipeline or project to provide a hotfix execution history. The collector queries selected CodePipeline/CodeBuild CloudTrail changes, but it does not yet call the pipeline APIs to collect execution records. This sandbox therefore does not prove the hotfix correlation path.

## Limits observed

- API test duration improved from 129 seconds to 39.9 seconds after reading Config resource types concurrently (up to four workers), Flow Log streams and selected S3 objects concurrently (up to five workers), using larger CloudWatch pages, and bounding CloudTrail pagination. Stage timing in the API log was about 1.5 seconds for AWS Config, 23 seconds for CloudTrail, 6 seconds for CloudWatch Logs, and 4.3 seconds for S3. It is faster but still too slow for a polished synchronous connect flow.
- The optimized run explicitly warned that the CloudTrail page limit was reached for EC2 and ELB. It collected 56 qualifying changes but can omit older changes behind more recent read-only events. A complete historical change feed needs incremental checkpoints or a customer event pipeline; simply increasing synchronous pagination would reintroduce long connect times.
- `coverageStatus` is `PARTIAL`, with `FLOW_LOGS_READ_DIRECTLY_NOT_RECORDED_BY_CONFIG`. Flow Logs are readable from their destinations, but AWS Config does not record the Flow Log resource type.
- CloudTrail results are capped at 200 mutating events per source; Flow Logs are capped at 7 days, 20 CloudWatch streams per group, 50 S3 objects and 20,000 normalized records.
- This run covers one account/Region only. It does not establish full organization-wide coverage, connect on-prem physical servers, or identify every IP/ENI as a business microservice.
- This collection establishes evidence availability only. The PathGuard agent has not yet used these live records to automatically classify unused/over-broad rules or propose a change.

## Reproduction

1. Start the local PathGuard API and Keycloak.
2. Give the API a short-lived runtime role that can assume the target role; do not inject the human operator credentials into the API.
3. Ensure the target role trusts the tenant-specific External ID and has only the read permissions listed in [AWS connection and network inventory](aws-connection-test.md).
4. Obtain a tenant JWT, call `POST /api/v1/aws/connections/test`, then read `GET /api/v1/aws/connections/{connectionId}/inventory`.
5. Review the collection counts, coverage, warnings, and time windows together. `connectionReady=true` does not mean evidence is complete.
