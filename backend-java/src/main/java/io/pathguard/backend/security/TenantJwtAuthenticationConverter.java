package io.pathguard.backend.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.UUID;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

/** Converts a verified JWT into a tenant-aware principal; an untrusted header is never consulted. */
public final class TenantJwtAuthenticationConverter implements Converter<Jwt, org.springframework.security.core.Authentication> {
    private final JwtGrantedAuthoritiesConverter scopes = new JwtGrantedAuthoritiesConverter();

    @Override
    public org.springframework.security.core.Authentication convert(Jwt jwt) {
        Object rawTenantId = jwt.getClaims().get("tenant_id");
        if (!(rawTenantId instanceof String tenantText) || tenantText.isBlank()) {
            throw new BadCredentialsException("Verified token is missing tenant_id");
        }

        UUID tenantId;
        try {
            tenantId = UUID.fromString(tenantText);
        } catch (IllegalArgumentException exception) {
            throw new BadCredentialsException("Verified token tenant_id is invalid", exception);
        }

        Collection<GrantedAuthority> authorities = new ArrayList<>();
        Collection<GrantedAuthority> scopeAuthorities = scopes.convert(jwt);
        if (scopeAuthorities != null) {
            authorities.addAll(scopeAuthorities);
        }
        authorities.add(new SimpleGrantedAuthority("ROLE_HUMAN"));
        Object rawRoles = jwt.getClaims().get("roles");
        if (rawRoles instanceof Collection<?> roles) {
            for (Object role : roles) {
                if (role instanceof String roleName && "TENANT_ADMIN".equals(roleName)) {
                    authorities.add(new SimpleGrantedAuthority("ROLE_TENANT_ADMIN"));
                }
            }
        } else if (rawRoles instanceof String roleName && "TENANT_ADMIN".equals(roleName)) {
            authorities.add(new SimpleGrantedAuthority("ROLE_TENANT_ADMIN"));
        }

        TenantIdentity identity = new TenantIdentity(tenantId, jwt.getSubject());
        return UsernamePasswordAuthenticationToken.authenticated(identity, jwt, authorities);
    }
}
