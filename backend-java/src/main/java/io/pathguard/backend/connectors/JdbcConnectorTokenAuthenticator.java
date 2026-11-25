package io.pathguard.backend.connectors;

import java.util.List;
import java.util.Optional;

import io.pathguard.backend.security.ConnectorIdentity;
import io.pathguard.backend.security.ConnectorTokenAuthenticator;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class JdbcConnectorTokenAuthenticator implements ConnectorTokenAuthenticator {
    private final JdbcTemplate jdbc;

    public JdbcConnectorTokenAuthenticator(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Override
    public Optional<ConnectorIdentity> authenticate(String rawToken) {
        if (!ConnectorRegistryService.isTokenShapeValid(rawToken, "pgc_")) {
            return Optional.empty();
        }
        String tokenHash = ConnectorRegistryService.sha256(rawToken);
        List<ConnectorIdentity> matches = jdbc.query("""
                SELECT connector_id, tenant_id, connector_type, connection_id, site_id, zone_id
                  FROM pathguard_connectors
                 WHERE credential_hash = ?
                   AND revoked_at IS NULL
                   AND expires_at > CURRENT_TIMESTAMP
                """,
                (rs, row) -> new ConnectorIdentity(
                        rs.getObject("tenant_id", java.util.UUID.class),
                        rs.getObject("connector_id", java.util.UUID.class),
                        rs.getString("connector_type"), rs.getString("connection_id"),
                        rs.getString("site_id"), rs.getString("zone_id")),
                tokenHash);
        if (matches.size() != 1) {
            return Optional.empty();
        }
        ConnectorIdentity identity = matches.getFirst();
        jdbc.update("UPDATE pathguard_connectors SET last_seen_at = CURRENT_TIMESTAMP WHERE connector_id = ?",
                identity.connectorId());
        return Optional.of(identity);
    }
}
