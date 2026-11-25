package io.pathguard.backend.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

class TenantJwtAuthenticationConverterTest {
    private final TenantJwtAuthenticationConverter converter = new TenantJwtAuthenticationConverter();

    @Test
    void createsTenantPrincipalFromVerifiedJwtClaims() {
        UUID tenantId = UUID.randomUUID();
        Jwt jwt = jwtBuilder().subject("user-123").claim("tenant_id", tenantId.toString())
                .claim("roles", java.util.List.of("TENANT_ADMIN")).build();

        UsernamePasswordAuthenticationToken authentication =
                (UsernamePasswordAuthenticationToken) converter.convert(jwt);

        assertThat(authentication.getPrincipal()).isEqualTo(new TenantIdentity(tenantId, "user-123"));
        assertThat(authentication.getAuthorities()).extracting("authority")
                .contains("ROLE_HUMAN", "ROLE_TENANT_ADMIN");
    }

    @Test
    void rejectsJwtWithoutTenantClaim() {
        Jwt jwt = jwtBuilder().subject("user-123").build();

        assertThatThrownBy(() -> converter.convert(jwt))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessageContaining("tenant_id");
    }

    private Jwt.Builder jwtBuilder() {
        Instant now = Instant.now();
        return Jwt.withTokenValue("unit-test-token")
                .header("alg", "RS256")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .claim("iss", "https://issuer.example.test");
    }
}
