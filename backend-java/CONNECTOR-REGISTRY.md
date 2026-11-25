# Connector registry API

This module binds each connector credential to a tenant on the server. It never accepts a tenant identifier in a request body or query parameter.

## User/admin endpoints

These routes require a JWT verified by the configured OIDC issuer. The token converter supplies `TenantIdentity` from the validated tenant claim. Create and revoke also require the verified `TENANT_ADMIN` role claim.

### Create a connector enrollment

`POST /api/v1/connectors/enrollments`

```json
{
  "connectorType": "AWS",
  "connectionId": "aws-org-prod",
  "expiresInSeconds": 600
}
```

For an on-prem site, use `connectorType: "ON_PREM"`, set `siteId`, and optionally set `zoneId`. For a CI/CD project, use `connectorType: "CI_CD"` with a `connectionId`; see `../collectors/README-cicd-connector.md`. Enrollment lifetime is limited to 60–900 seconds. The response includes a one-time `enrollmentToken`; it is not stored in plaintext.

### List and revoke

- `GET /api/v1/connectors` returns only connectors owned by the authenticated tenant. It never returns credential hashes or raw credentials.
- `DELETE /api/v1/connectors/{connectorId}` revokes only a connector in the authenticated tenant. Unknown and cross-tenant IDs both return 404.

## Connector endpoints

### Exchange enrollment

`POST /api/v1/connectors/enroll`

```json
{"enrollmentToken":"pge_..."}
```

The endpoint is public at the HTTP security layer only because a connector has no credential before enrollment. The service accepts only a valid, unexpired, unused random enrollment token; the enrollment is consumed atomically and cannot be replayed. The response includes a one-time 90-day `connectorToken`. Store it in the customer's secret store; the database retains only its SHA-256 hash. Revoke and enroll a new connector to rotate credentials.

The connector credential uses the `Authorization: PathGuardConnector <token>` scheme on explicitly supported connector endpoints. Keeping it distinct from `Bearer` prevents the user JWT resource-server filter from treating connector credentials as human JWTs. The backend connector-auth filter resolves it to a `ConnectorIdentity` containing tenant, connector, type and the registered site/connection scope. It must not be passed through as a client-authored tenant claim.

## Security boundaries and limits

- `tenant_id` and all unknown fields are rejected from enrollment requests.
- Tenant ID comes from verified user JWT for admin operations and from the connector registry lookup for connector operations.
- Connector type and site/connection references are bound when creating enrollment; the collector cannot change those bindings during token exchange.
- Tokens use 256 bits of cryptographic randomness and are stored as SHA-256 digests. Never log or retain raw tokens after returning them once.
- This module does not implement rate limiting, automatic token rotation, customer membership/invitation, or organization provisioning. Put rate limits at the API gateway and use the OIDC provider for user lifecycle.
- HTTPS is required in deployment. Do not expose connector endpoints over plaintext HTTP outside local development.
