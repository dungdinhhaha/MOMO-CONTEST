package io.pathguard.backend.connectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pathguard.backend.connectors.ConnectorRegistryService.ConnectorIssued;
import io.pathguard.backend.connectors.ConnectorRegistryService.ConnectorView;
import io.pathguard.backend.connectors.ConnectorRegistryService.EnrollmentIssued;
import io.pathguard.backend.security.ConnectorIdentity;
import io.pathguard.backend.security.TenantIdentity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.server.ResponseStatusException;

@SpringBootTest
@ActiveProfiles("test")
class ConnectorRegistryIntegrationTest {
    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private ConnectorRegistryService registry;

    @Autowired
    private JdbcConnectorTokenAuthenticator authenticator;

    @Autowired
    private ConnectorRegistryController controller;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void clearRegistry() {
        jdbc.update("DELETE FROM pathguard_connectors");
        jdbc.update("DELETE FROM pathguard_connector_enrollments");
    }

    @Test
    void enrollmentIsSingleUseAndOnlyCredentialHashIsStored() {
        UUID tenantId = UUID.randomUUID();
        EnrollmentIssued enrollment = registry.createEnrollment(tenantId, "user-1", "AWS",
                "aws-prod", null, null, 600);

        String enrollmentHash = jdbc.queryForObject(
                "SELECT enrollment_token_hash FROM pathguard_connector_enrollments WHERE enrollment_id = ?",
                String.class, enrollment.enrollmentId());
        assertEquals(ConnectorRegistryService.sha256(enrollment.enrollmentToken()), enrollmentHash);
        assertNotEquals(enrollment.enrollmentToken(), enrollmentHash);

        ConnectorIssued connector = registry.exchangeEnrollment(enrollment.enrollmentToken());
        String credentialHash = jdbc.queryForObject(
                "SELECT credential_hash FROM pathguard_connectors WHERE connector_id = ?",
                String.class, connector.connectorId());
        assertEquals(ConnectorRegistryService.sha256(connector.connectorToken()), credentialHash);
        assertNotEquals(connector.connectorToken(), credentialHash);

        ResponseStatusException replay = assertThrows(ResponseStatusException.class,
                () -> registry.exchangeEnrollment(enrollment.enrollmentToken()));
        assertEquals(401, replay.getStatusCode().value());

        ConnectorIdentity identity = authenticator.authenticate(connector.connectorToken()).orElseThrow();
        assertEquals(tenantId, identity.tenantId());
        assertEquals(connector.connectorId(), identity.connectorId());
        assertEquals("AWS", identity.connectorType());
        assertEquals("aws-prod", identity.connectionId());
    }

    @Test
    void expiredEnrollmentCannotBeExchanged() {
        EnrollmentIssued enrollment = registry.createEnrollment(UUID.randomUUID(), "user-2", "ON_PREM",
                null, "site-a", "payments-zone", 60);
        jdbc.update("UPDATE pathguard_connector_enrollments SET expires_at = ? WHERE enrollment_id = ?",
                Timestamp.from(Instant.now().minusSeconds(1)), enrollment.enrollmentId());

        ResponseStatusException expired = assertThrows(ResponseStatusException.class,
                () -> registry.exchangeEnrollment(enrollment.enrollmentToken()));
        assertEquals(401, expired.getStatusCode().value());
        assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM pathguard_connectors", Integer.class));
    }

    @Test
    void cicdEnrollmentIsTenantScopedAndUsesItsOwnConnectorType() {
        UUID tenant = UUID.randomUUID();
        EnrollmentIssued enrollment = registry.createEnrollment(tenant, "owner", "CI_CD",
                "github-wallet-prod", null, null, 600);
        ConnectorIssued issued = registry.exchangeEnrollment(enrollment.enrollmentToken());
        ConnectorIdentity identity = authenticator.authenticate(issued.connectorToken()).orElseThrow();
        assertEquals("CI_CD", identity.connectorType());
        assertEquals("github-wallet-prod", identity.connectionId());
        assertEquals(tenant, identity.tenantId());
    }

    @Test
    void listAndRevokeAreTenantScopedAndRevocationBlocksConnector() {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();
        EnrollmentIssued enrollment = registry.createEnrollment(tenantA, "owner-a", "ON_PREM",
                null, "shared-site-name", "zone-1", null);
        ConnectorIssued connector = registry.exchangeEnrollment(enrollment.enrollmentToken());

        List<ConnectorView> visibleToA = registry.listForTenant(tenantA);
        List<ConnectorView> visibleToB = registry.listForTenant(tenantB);
        assertEquals(1, visibleToA.size());
        assertEquals(0, visibleToB.size());

        ResponseStatusException crossTenantRevoke = assertThrows(ResponseStatusException.class,
                () -> registry.revoke(tenantB, connector.connectorId()));
        assertEquals(404, crossTenantRevoke.getStatusCode().value());
        assertTrue(authenticator.authenticate(connector.connectorToken()).isPresent());

        registry.revoke(tenantA, connector.connectorId());
        assertTrue(authenticator.authenticate(connector.connectorToken()).isEmpty());
    }

    @Test
    void enrollmentRejectsClientTenantIdAndRequiresTenantAdmin() throws Exception {
        TenantIdentity tenant = new TenantIdentity(UUID.randomUUID(), "user-3");
        var member = UsernamePasswordAuthenticationToken.authenticated(tenant, null,
                List.of(new SimpleGrantedAuthority("ROLE_HUMAN")));
        var admin = UsernamePasswordAuthenticationToken.authenticated(tenant, null,
                List.of(new SimpleGrantedAuthority("ROLE_HUMAN"),
                        new SimpleGrantedAuthority("ROLE_TENANT_ADMIN")));

        var body = objectMapper.readTree("""
                {"connectorType":"AWS","connectionId":"aws-prod"}
                """);
        ResponseStatusException forbidden = assertThrows(ResponseStatusException.class,
                () -> controller.createEnrollment(tenant, member, body));
        assertEquals(403, forbidden.getStatusCode().value());

        var forgedTenantBody = objectMapper.readTree("""
                {"tenant_id":"00000000-0000-0000-0000-000000000000",
                 "connectorType":"AWS","connectionId":"aws-prod"}
                """);
        ResponseStatusException rejected = assertThrows(ResponseStatusException.class,
                () -> controller.createEnrollment(tenant, admin, forgedTenantBody));
        assertEquals(400, rejected.getStatusCode().value());
    }
}
