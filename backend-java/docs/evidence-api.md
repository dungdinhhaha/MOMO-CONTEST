# PathGuard Evidence API

This module adds a versioned evidence-bundle endpoint. It persists the authenticated connector's tenant/connection identity separately from client payload and exposes a tenant-filtered listing API for authenticated users.

## Connector upload

`POST /api/v1/evidence/bundles` requires a connector credential issued by the connector registry in the `PathGuardConnector` authorization scheme. The security filter resolves that credential to a `ConnectorIdentity`; the controller does not accept a tenant ID from the request. The JSON body is capped at 2 MiB and 5,000 records.

Example body:

```json
{
  "schema_version": "pathguard.evidence-bundle.v1",
  "source_type": "AWS",
  "connection_id": "aws-prod",
  "collected_at": "2026-11-24T10:01:00Z",
  "records": [
    {
      "id": "config-item-123",
      "evidence_type": "aws-config-resource",
      "resource_key": "123456789012/ap-southeast-2/AWS::EC2::VPC/vpc-abc",
      "observed_at": "2026-11-24T10:00:00Z",
      "payload": {"resource_type": "AWS::EC2::VPC", "resource_id": "vpc-abc"}
    }
  ],
  "coverage": {
    "status": "partial",
    "window_start": "2026-11-24T09:00:00Z",
    "window_end": "2026-11-24T10:00:00Z"
  }
}
```

The body must not contain a `tenant_id`/`tenantId` claim. `source_type` must match the authenticated connector type (`AWS`, `ON_PREM`, or `CI_CD`). Connection, site, zone, and connector references may be included only when they match the authenticated connector scope. Credential-like field names such as `password`, `secret`, access/private keys, or token fields are rejected to reduce accidental secret ingestion. AWS JSONL/manifests, on-prem collector output, and selected CI/CD run metadata are normalized into this envelope before upload. For on-prem, `site_kind` is provenance supplied by the connector configuration (for example `physical` or `aws_simulation`); it is not proof of physical infrastructure.

Repeated byte-equivalent normalized bundles from the same tenant and connector are idempotent and return the existing bundle ID.

## Human read

`GET /api/v1/evidence?since=2026-11-24T00:00:00Z&until=2026-11-25T00:00:00Z&limit=50&offset=0` requires a verified human JWT. The tenant ID comes from `TenantIdentity`, derived from the JWT. There is no tenant query parameter. SQL always includes `WHERE tenant_id = ?`; pagination is bounded to 100 records per request.

## Data model notes

- The database stores server-derived tenant, connector, and scope columns separately from normalized bundle JSON.
- Stable AWS resource keys should include account ID, Region, resource type, and resource ID. CIDR is an attribute, never a resource key.
- Coverage is persisted as reported by the collector and is not treated as proof of completeness or physical-site provenance.
- The module does not yet pass evidence into an AI agent. A later agent-tool adapter must take its tenant from the verified request context and use bounded queries.

## On-prem connector heartbeat

The on-prem connector initiates outbound HTTPS. PathGuard does not open connections into private customer networks or probe on-prem addresses itself.

1. A tenant admin creates a short-lived `ON_PREM` enrollment with `siteId` and optional `zoneId` at `POST /api/v1/connectors/enrollments`.
2. The customer runs the collector with the one-time `enrollmentToken` in `PATHGUARD_ENROLLMENT_TOKEN` (never in JSON config or command arguments). The collector exchanges it at `POST /api/v1/connectors/enroll`.
3. The collector saves the returned connector token locally (mode 0600 where supported) and sends source checks to `POST /api/v1/site-connector/heartbeat` using outbound HTTPS.
4. A tenant user checks status using `GET /api/v1/connectors/{connectorId}/status`. The query is filtered by the tenant in the verified JWT.

Heartbeat example:

```json
{
  "checkedAt": "2026-11-24T12:00:00Z",
  "overallStatus": "PARTIAL",
  "sources": [
    { "name": "ip_routes", "status": "OK", "checkedAt": "2026-11-24T12:00:00Z" },
    { "name": "firewall_export", "status": "NOT_CONFIGURED", "checkedAt": "2026-11-24T12:00:00Z" }
  ]
}
```

Allowed source states are `OK`, `UNAVAILABLE`, `ERROR`, `NOT_CONFIGURED`, and `NOT_SELECTED`. Error details are short `errorCode` values; raw command output is not accepted. Tenant IDs and arbitrary fields are rejected. AWS connectors cannot call this endpoint.

The optional collector `backend` config block contains only `base_url` and `credential_file`; it must not contain credentials. Existing connector credentials are reused. For first enrollment, retrieve the one-time token from the app/secret manager into the process environment, then run the collector. The collector removes it from that process environment after exchange. Once enrolled, each run sends both a heartbeat and a normalized evidence bundle to the backend over outbound HTTPS.
