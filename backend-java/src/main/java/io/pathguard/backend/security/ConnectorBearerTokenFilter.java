package io.pathguard.backend.security;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/** Accepts dedicated connector credentials only on supported ingestion endpoints. */
public final class ConnectorBearerTokenFilter extends OncePerRequestFilter {
    private static final String CONNECTOR_AUTH_SCHEME = "PathGuardConnector ";
    private static final java.util.Set<String> CONNECTOR_PATHS = java.util.Set.of(
            "/api/v1/evidence/bundles", "/api/v1/site-connector/heartbeat");
    private final ConnectorTokenAuthenticator authenticator;

    public ConnectorBearerTokenFilter(ConnectorTokenAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        if (path == null || path.isEmpty()) {
            String uri = request.getRequestURI();
            String context = request.getContextPath();
            path = uri.startsWith(context) ? uri.substring(context.length()) : uri;
        }
        return !"POST".equalsIgnoreCase(request.getMethod()) || !CONNECTOR_PATHS.contains(path);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.regionMatches(true, 0, CONNECTOR_AUTH_SCHEME, 0,
                CONNECTOR_AUTH_SCHEME.length())) {
            String rawToken = header.substring(CONNECTOR_AUTH_SCHEME.length()).trim();
            if (!rawToken.isEmpty()) {
                Optional<ConnectorIdentity> identity = authenticator.authenticate(rawToken);
                identity.ifPresent(connector -> SecurityContextHolder.getContext().setAuthentication(
                        UsernamePasswordAuthenticationToken.authenticated(
                                connector, null, List.of(new SimpleGrantedAuthority("ROLE_CONNECTOR")))));
            }
        }
        chain.doFilter(request, response);
    }
}
