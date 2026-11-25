package io.pathguard.backend.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

class ConnectorBearerTokenFilterTest {
    private static final ConnectorIdentity CONNECTOR = new ConnectorIdentity(
            UUID.randomUUID(), UUID.randomUUID(), "ON_PREM", null, "site-a", "zone-a");

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void authenticatesDedicatedConnectorScheme() throws Exception {
        var filter = new ConnectorBearerTokenFilter(token -> {
            assertEquals("pgc-test-token", token);
            return Optional.of(CONNECTOR);
        });
        var request = request("PathGuardConnector pgc-test-token");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertSame(CONNECTOR, SecurityContextHolder.getContext().getAuthentication().getPrincipal());
    }

    @Test
    void doesNotInterpretHumanBearerTokenAsConnectorCredential() throws Exception {
        var filter = new ConnectorBearerTokenFilter(token -> {
            throw new AssertionError("Bearer credentials must not reach the connector authenticator");
        });

        filter.doFilter(request("Bearer pgc-test-token"), new MockHttpServletResponse(), new MockFilterChain());

        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    private static MockHttpServletRequest request(String authorization) {
        var request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.setServletPath("/api/v1/site-connector/heartbeat");
        request.addHeader("Authorization", authorization);
        return request;
    }
}
