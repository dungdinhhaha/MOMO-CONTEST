package io.pathguard.backend.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pathguard.backend.security.TenantIdentity;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.server.ResponseStatusException;

class AwsConnectionControllerTest {
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void requiresTenantAdminAndRejectsClientTenantId() throws Exception {
        var probe = new AwsReadOnlyProbe() {
            @Override
            public ProbeResult probe(String roleArn, String externalId, String expectedAccountId, String region,
                                     UUID tenantId) {
                throw new AssertionError("Probe must not run for a non-admin or forged tenant body");
            }
        };
        var controller = new AwsConnectionController(
                new AwsConnectionService(probe, org.mockito.Mockito.mock(AwsNetworkSnapshotService.class)),
                new AwsExternalIdService("integration-test-secret-value-that-is-at-least-32-bytes"),
                org.mockito.Mockito.mock(AwsNetworkSnapshotService.class));
        var tenant = new TenantIdentity(UUID.randomUUID(), "engineer");
        var member = UsernamePasswordAuthenticationToken.authenticated(tenant, null,
                List.of(new SimpleGrantedAuthority("ROLE_HUMAN")));
        var admin = UsernamePasswordAuthenticationToken.authenticated(tenant, null,
                List.of(new SimpleGrantedAuthority("ROLE_HUMAN"),
                        new SimpleGrantedAuthority("ROLE_TENANT_ADMIN")));

        var payload = mapper.readTree("""
                {"connectionId":"aws-prod",
                 "roleArn":"arn:aws:iam::123456789012:role/PathGuardReadOnly",
                 "expectedAccountId":"123456789012",
                 "region":"ap-southeast-1"}
                """);
        var forbidden = assertThrows(ResponseStatusException.class, () -> controller.test(tenant, member, payload));
        assertEquals(403, forbidden.getStatusCode().value());

        var forgedPayload = mapper.readTree("""
                {"tenant_id":"00000000-0000-0000-0000-000000000000",
                 "connectionId":"aws-prod",
                 "roleArn":"arn:aws:iam::123456789012:role/PathGuardReadOnly",
                 "expectedAccountId":"123456789012",
                 "region":"ap-southeast-1"}
                """);
        var badRequest = assertThrows(ResponseStatusException.class,
                () -> controller.test(tenant, admin, forgedPayload));
        assertEquals(400, badRequest.getStatusCode().value());

        var suppliedExternalId = mapper.readTree("""
                {"connectionId":"aws-prod", "roleArn":"arn:aws:iam::123456789012:role/PathGuardReadOnly",
                 "expectedAccountId":"123456789012", "region":"ap-southeast-1",
                 "externalId":"caller-controlled"}
                """);
        var externalIdRejected = assertThrows(ResponseStatusException.class,
                () -> controller.test(tenant, admin, suppliedExternalId));
        assertEquals(400, externalIdRejected.getStatusCode().value());
    }
}
