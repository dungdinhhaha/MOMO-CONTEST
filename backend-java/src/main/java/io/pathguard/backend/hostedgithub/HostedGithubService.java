package io.pathguard.backend.hostedgithub;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.pathguard.backend.evidence.EvidenceBundleService;
import io.pathguard.backend.hostedgithub.HostedGithubRepository.Source;
import io.pathguard.backend.security.ConnectorIdentity;
import io.pathguard.backend.security.TenantIdentity;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class HostedGithubService {
    private static final Pattern REPOSITORY = Pattern.compile("[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]{1,80}");
    private static final Pattern LABEL = Pattern.compile("[A-Za-z0-9_.:/ -]{1,128}");
    private final HostedGithubRepository repository;
    private final PublicGithubClient github;
    private final EvidenceBundleService evidence;
    private final ObjectMapper mapper;
    private final SecureRandom random = new SecureRandom();

    public HostedGithubService(HostedGithubRepository repository, PublicGithubClient github,
                               EvidenceBundleService evidence, ObjectMapper mapper) {
        this.repository = repository;
        this.github = github;
        this.evidence = evidence;
        this.mapper = mapper;
    }

    @Transactional
    public Source create(TenantIdentity tenant, NewSource input) {
        String repo = valid(input.repository(), REPOSITORY, "repository");
        String workflow = valid(input.workflowName(), LABEL, "workflowName");
        String service = valid(input.service(), LABEL, "service");
        String environment = valid(input.environment(), LABEL, "environment");
        if (repository.countForTenant(tenant.tenantId()) >= 10) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Public GitHub source limit reached");
        }
        JsonNode metadata = github.repository(repo);
        if (!metadata.isObject() || metadata.path("private").asBoolean(true)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Repository is not public");
        }
        UUID id = UUID.randomUUID();
        Instant now = Instant.now();
        Source row = new Source(id, tenant.tenantId(), repo, workflow, service, environment,
                "github-public-" + id, tenant.subject(), now, null, null, true);
        byte[] unusedCredential = new byte[32];
        random.nextBytes(unusedCredential);
        try {
            repository.insert(row, sha256(unusedCredential));
        } catch (DuplicateKeyException duplicate) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Source already registered");
        }
        return row;
    }

    public List<Source> list(TenantIdentity tenant) {
        return repository.list(tenant.tenantId());
    }

    @Transactional
    public void disable(TenantIdentity tenant, UUID sourceId) {
        if (!repository.disable(tenant.tenantId(), sourceId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Source not found");
        }
    }

    public Source sync(TenantIdentity tenant, UUID sourceId) {
        Source source = repository.find(tenant.tenantId(), sourceId);
        if (source == null || !source.enabled()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Source not found");
        }
        if (!repository.claim(source, Instant.now())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Source is already scheduled for polling");
        }
        poll(source);
        return repository.find(tenant.tenantId(), sourceId);
    }

    @Scheduled(fixedDelayString = "${pathguard.hosted-github.poll-ms:300000}",
            initialDelayString = "${pathguard.hosted-github.initial-delay-ms:10000}")
    public void pollDue() {
        for (Source source : repository.due(20)) {
            if (repository.claim(source, Instant.now())) {
                poll(source);
            }
        }
    }

    private void poll(Source source) {
        try {
            JsonNode response = github.runs(source.repository());
            JsonNode runs = response.path("workflow_runs");
            if (!runs.isArray()) {
                throw new PublicGithubClient.GithubSourceException("GITHUB_INVALID_RESPONSE");
            }
            Instant now = Instant.now();
            List<Map<String, Object>> records = new ArrayList<>();
            for (JsonNode run : runs) {
                if (!source.workflowName().equals(run.path("name").asText())) {
                    continue;
                }
                String updated = run.path("updated_at").asText("");
                Instant updatedAt;
                try { updatedAt = Instant.parse(updated); }
                catch (Exception invalid) { continue; }
                if (source.lastSuccessAt() != null && !updatedAt.isAfter(source.lastSuccessAt())) {
                    continue;
                }
                String runId = run.path("id").asText("");
                if (!runId.matches("[0-9]{1,30}")) { continue; }
                Map<String, Object> details = new LinkedHashMap<>();
                details.put("provider", "github_actions");
                details.put("repository", source.repository());
                details.put("workflow", source.workflowName());
                details.put("service", source.serviceName());
                details.put("environment", source.environmentName());
                details.put("mapping_source", "customer_config");
                details.put("run_id", runId);
                details.put("status", run.path("status").asText("unknown"));
                details.put("conclusion", run.path("conclusion").asText("unknown"));
                details.put("commit_sha", run.path("head_sha").asText(""));
                details.put("branch", run.path("head_branch").asText(""));
                details.put("run_url", "https://github.com/" + source.repository()
                        + "/actions/runs/" + runId);
                details.put("deployment_job_observed", false);
                details.put("runtime_version_verified", false);
                details.put("provenance", "live_provider_api");
                records.add(Map.of("id", "github-run-" + runId + "-" + updatedAt.toEpochMilli(),
                        "evidence_type", "cicd-run",
                        "resource_key", "cicd/github_actions/" + source.repository() + "/" + runId,
                        "observed_at", updatedAt.toString(), "payload", details));
            }
            if (!records.isEmpty()) {
                Map<String, Object> bundle = Map.of(
                        "schema_version", "pathguard.evidence-bundle.v1",
                        "source_type", "CI_CD", "connection_id", source.connectionId(),
                        "collected_at", now.toString(), "records", records,
                        "coverage", Map.of("status", "partial",
                                "window_start", now.minusSeconds(1).toString(),
                                "window_end", now.toString()));
                evidence.ingest(mapper.writeValueAsBytes(bundle), new ConnectorIdentity(
                        source.tenantId(), source.sourceId(), "CI_CD", source.connectionId(), null, null));
            }
            repository.success(source.sourceId(), now);
        } catch (Exception failure) {
            String code = failure instanceof PublicGithubClient.GithubSourceException
                    ? failure.getMessage() : "SYNC_FAILED";
            repository.error(source.sourceId(), code);
        }
    }

    private static String valid(String value, Pattern pattern, String field) {
        if (value == null || value.length() > 128 || !pattern.matcher(value).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid " + field);
        }
        return value;
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (Exception exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }

    public record NewSource(String repository, String workflowName, String service, String environment) {}
}
