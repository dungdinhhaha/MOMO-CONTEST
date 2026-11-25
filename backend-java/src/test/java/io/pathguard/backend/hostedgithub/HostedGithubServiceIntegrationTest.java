package io.pathguard.backend.hostedgithub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pathguard.backend.evidence.EvidenceBundleService;
import io.pathguard.backend.security.TenantIdentity;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.server.ResponseStatusException;

@SpringBootTest
@ActiveProfiles("test")
class HostedGithubServiceIntegrationTest {
    @Autowired HostedGithubService service;
    @Autowired EvidenceBundleService evidence;
    @Autowired JdbcTemplate jdbc;
    @Autowired ObjectMapper mapper;
    @MockitoBean PublicGithubClient github;

    @BeforeEach
    void clear() {
        jdbc.update("DELETE FROM pathguard_evidence_bundle");
        jdbc.update("DELETE FROM pathguard_hosted_github_source");
        jdbc.update("DELETE FROM pathguard_connectors");
        jdbc.update("DELETE FROM pathguard_connector_enrollments");
    }

    @Test
    void customerRegistersPublicRepoAndOnlyOwnTenantSeesEvidence() throws Exception {
        var first = new TenantIdentity(UUID.randomUUID(), "owner-a");
        var second = new TenantIdentity(UUID.randomUUID(), "owner-b");
        when(github.repository("owner/repo")).thenReturn(mapper.readTree("{\"private\":false}"));
        when(github.runs("owner/repo")).thenReturn(mapper.readTree("""
                {"workflow_runs":[{"id":42,"name":"CI","updated_at":"2026-11-25T00:00:00Z",
                "status":"completed","conclusion":"success","head_sha":"abc","head_branch":"master"}]}
                """));
        var registered = service.create(first,
                new HostedGithubService.NewSource("owner/repo", "CI", "wallet-api", "ci"));
        assertEquals(1, service.list(first).size());
        assertEquals(0, service.list(second).size());
        assertEquals(404, assertThrows(ResponseStatusException.class,
                () -> service.sync(second, registered.sourceId())).getStatusCode().value());

        service.sync(first, registered.sourceId());
        assertEquals(1, evidence.list(first, null, null, 10, 0).items().size());
        assertEquals(0, evidence.list(second, null, null, 10, 0).items().size());
        assertEquals("CI_CD", evidence.list(first, null, null, 10, 0).items().getFirst().connectorType());

        service.disable(first, registered.sourceId());
        assertEquals(false, service.list(first).getFirst().enabled());
    }

    @Test
    void privateRepoIsRejectedBeforeRegistration() throws Exception {
        var tenant = new TenantIdentity(UUID.randomUUID(), "owner");
        when(github.repository("owner/private")).thenReturn(mapper.readTree("{\"private\":true}"));
        assertEquals(400, assertThrows(ResponseStatusException.class,
                () -> service.create(tenant, new HostedGithubService.NewSource(
                        "owner/private", "CI", "wallet-api", "ci"))).getStatusCode().value());
        assertEquals(0, service.list(tenant).size());
    }
}
