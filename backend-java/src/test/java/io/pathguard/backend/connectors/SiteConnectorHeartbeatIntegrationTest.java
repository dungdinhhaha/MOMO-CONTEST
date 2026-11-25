package io.pathguard.backend.connectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pathguard.backend.security.ConnectorIdentity;
import io.pathguard.backend.security.TenantIdentity;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.server.ResponseStatusException;

@SpringBootTest
@ActiveProfiles("test")
@AutoConfigureMockMvc
class SiteConnectorHeartbeatIntegrationTest {
    @Autowired JdbcTemplate jdbc;
    @Autowired ConnectorRegistryService registry;
    @Autowired SiteConnectorHeartbeatController controller;
    @Autowired ObjectMapper mapper;
    @Autowired MockMvc mockMvc;

    @BeforeEach
    void clear() {
        jdbc.update("DELETE FROM pathguard_site_connector_heartbeats");
        jdbc.update("DELETE FROM pathguard_connectors");
        jdbc.update("DELETE FROM pathguard_connector_enrollments");
    }

    @Test
    void onPremConnectorPostsStatusAndOnlyItsTenantCanReadIt() throws Exception {
        UUID tenantA = UUID.randomUUID();
        var enrollment = registry.createEnrollment(tenantA, "owner", "ON_PREM", null, "dc-east", "payments", null);
        var issued = registry.exchangeEnrollment(enrollment.enrollmentToken());
        var connector = new ConnectorIdentity(tenantA, issued.connectorId(), "ON_PREM", null,
                "dc-east", "payments");
        var connectorAuth = UsernamePasswordAuthenticationToken.authenticated(connector, null,
                List.of(new SimpleGrantedAuthority("ROLE_CONNECTOR")));
        Instant now = Instant.now();
        var body = mapper.readTree("""
                {"checkedAt":"%s","overallStatus":"PARTIAL","sources":[
                  {"name":"host_routes","status":"OK","checkedAt":"%s"},
                  {"name":"firewall_export","status":"NOT_CONFIGURED","checkedAt":"%s","errorCode":"SOURCE_NOT_CONFIGURED"}]}
                """.formatted(now, now, now));

        var accepted = controller.heartbeat(body, connectorAuth);
        assertTrue(accepted.accepted());
        assertTrue(accepted.backendReachable());
        assertEquals(issued.connectorId(), accepted.connectorId());

        var tenantAuth = UsernamePasswordAuthenticationToken.authenticated(new TenantIdentity(tenantA, "owner"), null,
                List.of(new SimpleGrantedAuthority("ROLE_HUMAN")));
        var status = controller.status(issued.connectorId(), tenantAuth);
        assertEquals("PARTIAL", status.overallStatus());
        assertEquals("dc-east", status.siteId());
        assertEquals(2, status.sources().size());

        UUID tenantB = UUID.randomUUID();
        var otherTenant = UsernamePasswordAuthenticationToken.authenticated(new TenantIdentity(tenantB, "other"), null,
                List.of(new SimpleGrantedAuthority("ROLE_HUMAN")));
        ResponseStatusException hidden = assertThrows(ResponseStatusException.class,
                () -> controller.status(issued.connectorId(), otherTenant));
        assertEquals(404, hidden.getStatusCode().value());
    }

    @Test
    void heartbeatRejectsForgedTenantClaimsAndAwsConnectors() throws Exception {
        UUID tenant = UUID.randomUUID();
        var enrollment = registry.createEnrollment(tenant, "owner", "AWS", "aws-main", null, null, null);
        var issued = registry.exchangeEnrollment(enrollment.enrollmentToken());
        var aws = new ConnectorIdentity(tenant, issued.connectorId(), "AWS", "aws-main", null, null);
        var connectorAuth = UsernamePasswordAuthenticationToken.authenticated(aws, null,
                List.of(new SimpleGrantedAuthority("ROLE_CONNECTOR")));
        var sample = mapper.readTree("""
                {"checkedAt":"%s","overallStatus":"OK","sources":[{"name":"host","status":"OK","checkedAt":"%s"}]}
                """.formatted(Instant.now(), Instant.now()));
        ResponseStatusException forbidden = assertThrows(ResponseStatusException.class,
                () -> controller.heartbeat(sample, connectorAuth));
        assertEquals(403, forbidden.getStatusCode().value());

        var onPremEnrollment = registry.createEnrollment(tenant, "owner", "ON_PREM", null, "dc-east", null, null);
        var onPrem = registry.exchangeEnrollment(onPremEnrollment.enrollmentToken());
        var onPremAuth = UsernamePasswordAuthenticationToken.authenticated(
                new ConnectorIdentity(tenant, onPrem.connectorId(), "ON_PREM", null, "dc-east", null), null,
                List.of(new SimpleGrantedAuthority("ROLE_CONNECTOR")));
        var forged = mapper.readTree("""
                {"tenant_id":"%s","checkedAt":"%s","overallStatus":"OK","sources":[{"name":"host","status":"OK","checkedAt":"%s"}]}
                """.formatted(UUID.randomUUID(), Instant.now(), Instant.now()));
        ResponseStatusException rejected = assertThrows(ResponseStatusException.class,
                () -> controller.heartbeat(forged, onPremAuth));
        assertEquals(400, rejected.getStatusCode().value());
    }

    @Test
    void connectorBearerTokenAuthenticatesHeartbeatOverHttp() throws Exception {
        UUID tenant = UUID.randomUUID();
        var enrollment = registry.createEnrollment(tenant, "owner", "ON_PREM", null, "dc-http", "zone-a", null);
        var issued = registry.exchangeEnrollment(enrollment.enrollmentToken());
        String checkedAt = Instant.now().toString();
        String body = """
                {"checkedAt":"%s","overallStatus":"PARTIAL","sources":[
                  {"name":"host","status":"ERROR","checkedAt":"%s","errorCode":"LOCAL_SMOKE"}]}
                """.formatted(checkedAt, checkedAt);

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/api/v1/site-connector/heartbeat")
                        .header("Authorization", "PathGuardConnector " + issued.connectorToken())
                        .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .jsonPath("$.accepted").value(true));
    }
}
