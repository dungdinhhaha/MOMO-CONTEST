# PathGuard Spring Boot backend

Tenant-scoped API for assuming an AWS read-only role, collecting AWS network inventory, selected CloudTrail changes and existing Flow Log records, enrolling outbound on-prem and CI/CD connectors, receiving on-prem heartbeats and storing normalized evidence bundles. AWS collection is one account and Region per request and has explicit time and record caps. On-prem and CI/CD connectors upload normalized evidence with tenant-bound credentials; the app can query stored bundles by authenticated tenant.

## Run with Docker

From this directory, generate a random HMAC secret for AWS External IDs, then start the API, PostgreSQL, and a local Keycloak realm:

```powershell
$env:PATHGUARD_AWS_EXTERNAL_ID_HMAC_SECRET = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
docker compose up --build -d
```

Health endpoint: `http://localhost:8080/actuator/health`. The API, PostgreSQL, and local Keycloak ports are bound to `127.0.0.1`; Keycloak is preloaded with a **development-only** tenant admin (`demo-admin` / `pathguard-demo-only`). This realm and password are for local testing only and must not be used in a hosted deployment. For production, configure your own OIDC issuer and secret manager. AWS tests additionally require the API runtime identity to call `sts:AssumeRole` for customer roles. Compose does not inject AWS credentials. Do not add static AWS keys to the repository or image.

See [connection test workflow](docs/connection-test-workflow.md) for AWS and on-prem setup and the exact API requests.

## Run tests

With Docker Desktop running:

```powershell
docker run --rm -v "${PWD}:/workspace" -w /workspace maven:3.9.9-eclipse-temurin-21 ./mvnw -B clean verify
```

Java unit and integration tests use H2 and mock AWS probes; they do not contact a live AWS account. Python on-prem connector unit tests are in `../test_site_connector.py`. The local API upload path can be exercised with `../test_onprem_upload_e2e.py` after starting Compose and setting `PATHGUARD_E2E_USERNAME` and `PATHGUARD_E2E_PASSWORD`; it creates a simulated site and uploads synthetic normalized evidence, and does not contact AWS or prove physical on-prem coverage. To test the live AWS connector, see `docs/aws-connection-test.md`.

## Security boundaries

- Human tenant identity comes from a verified JWT. There is no tenant-header bypass.
- Connector identity comes from a hashed bearer token created by one-time enrollment. The backend derives tenant, connector type, site, and zone from that token.
- On-prem connectivity is outbound-only over HTTPS. The backend cannot reach private on-prem addresses unless the customer separately provisions private network connectivity.
- AWS credentials are short-lived STS credentials held in memory during the probe. The external ID is derived from the verified tenant and connection ID using the deployment HMAC secret.
- Keep production secrets in a secret manager; deploy behind TLS; configure backups, rate limits, monitoring, and a production OIDC provider before exposing the API publicly.
