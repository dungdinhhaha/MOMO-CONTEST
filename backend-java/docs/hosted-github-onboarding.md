# Hosted public GitHub onboarding

An authenticated tenant administrator can register a public GitHub Actions source through the PathGuard API. The backend verifies that the repository is public, stores the repository/workflow/service/environment mapping under the verified tenant ID, and polls GitHub every five minutes. No customer-side script, EC2 session, GitHub PAT, or connector token is required for this public-repository path.

```http
POST /api/v1/hosted/github
Authorization: Bearer <tenant-admin JWT>
Content-Type: application/json

{
  "repository": "dungdinhhaha/MOMO-CONTEST",
  "workflowName": "PathGuard connector CI",
  "service": "pathguard-connector",
  "environment": "ci"
}
```

Use `GET /api/v1/hosted/github` to list the authenticated tenant's sources and see `lastSuccessAt` or `lastErrorCode`. `POST /api/v1/hosted/github/{sourceId}/sync` requests an immediate poll if the source is due. `DELETE /api/v1/hosted/github/{sourceId}` stops polling. The source and all stored evidence are isolated by the tenant ID from the verified JWT. Each tenant can register up to ten active public sources.

The collector reads at most 50 recent runs of the chosen workflow. It records a CI run as provider evidence; `deployment_job_observed=false` and `runtime_version_verified=false` until a separate deployment connector verifies those facts. The service/environment mapping is a customer declaration, not a GitHub assertion. A `GITHUB_HTTP_403` status can indicate the shared unauthenticated GitHub API limit. Large installations need a GitHub App with installation-scoped permissions and rate-limit handling.

Private repositories are rejected by this endpoint. Supporting them requires a GitHub App installation flow, short-lived installation tokens, installation-to-tenant binding, and webhook signature verification. On-premises systems still need an outbound site connector because the hosted API cannot reach private network devices.
