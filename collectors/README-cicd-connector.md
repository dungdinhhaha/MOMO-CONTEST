# PathGuard CI/CD connector

The CI/CD collector polls the selected GitHub Actions or GitLab CI project using a read-only provider token. It sends selected workflow and deployment-job metadata to PathGuard through an outbound HTTPS connection. The provider token stays in the collector process environment and is never included in the evidence bundle. Each PathGuard connector is enrolled for one tenant and `connection_id`; the backend derives tenant identity from its credential, not the payload.

## Onboard one repository and environment

1. A tenant admin calls `POST /api/v1/connectors/enrollments` with `{"connectorType":"CI_CD","connectionId":"github-wallet-prod"}`. Save the one-use `enrollmentToken` securely.
2. Copy `cicd-connector.example.json` to a customer-owned config file. Set the provider (`github_actions` or `gitlab_ci`), repository/project, service, environment, workflow names and deploy job names. Neither the provider token nor enrollment token belongs in this file.
3. For a private GitHub repository or GitLab project, give a provider token read access only to the specified repository/project and its Actions/pipeline metadata, then set `PATHGUARD_CICD_API_TOKEN`. A public GitHub repository can be read without this token, subject to GitHub's unauthenticated API rate limit. For the first run, set `PATHGUARD_ENROLLMENT_TOKEN` in the collector process environment.
4. Run `python -m collectors.cicd_connector --config <config.json> --interval 300` from the PathGuard project directory, or package it using `infra/cicd-connector/Dockerfile`. Mount the config read-only and a persistent `/state` volume for the PathGuard connector credential and sync cursor.

`--interval 0` runs once. The backend accepts the evidence as `source_type=CI_CD`. A second repository, environment, or tenant uses a separate connection ID, credential and state directory. The connector reads the most recent 100 runs per cycle; coverage reports when that window is truncated. It resends a run only when its provider `updated_at` changes, and sends coverage on every cycle.

The configured workflow/job names identify **candidate deployment runs**. A successful run and matching deployment job do not prove that the target is running that version or that a hotfix was approved. PathGuard must still correlate the run with cloud changes, workload identity, flow logs and operational evidence.
