package io.pathguard.backend.connectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.pathguard.backend.security.ConnectorIdentity;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class SiteConnectorHeartbeatService {
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public SiteConnectorHeartbeatService(JdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    @Transactional
    public HeartbeatAccepted record(ConnectorIdentity connector, Instant checkedAt, String overallStatus,
                                    JsonNode sources) {
        if (connector == null || !"ON_PREM".equals(connector.connectorType())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "ON_PREM connector required");
        }
        Instant now = Instant.now();
        if (checkedAt.isAfter(now.plusSeconds(300)) || checkedAt.isBefore(now.minusSeconds(86400))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "checkedAt must be within the last 24 hours");
        }
        String json;
        try {
            json = mapper.writeValueAsString(sources);
        } catch (JsonProcessingException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Source checks could not be normalized");
        }
        List<UUID> active = jdbc.query("""
                SELECT connector_id FROM pathguard_connectors
                 WHERE connector_id = ? AND tenant_id = ? AND connector_type = 'ON_PREM'
                   AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP
                 FOR UPDATE
                """, (rs, row) -> rs.getObject("connector_id", UUID.class),
                connector.connectorId(), connector.tenantId());
        if (active.size() != 1) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Connector is revoked or expired");
        }
        int updated = jdbc.update("""
                UPDATE pathguard_site_connector_heartbeats
                   SET overall_status = ?, checked_at = ?, received_at = ?, source_checks = ?
                 WHERE connector_id = ?
                """, overallStatus, java.sql.Timestamp.from(checkedAt), java.sql.Timestamp.from(now), json,
                connector.connectorId());
        if (updated == 0) {
            jdbc.update("""
                    INSERT INTO pathguard_site_connector_heartbeats
                        (connector_id, overall_status, checked_at, received_at, source_checks)
                    VALUES (?, ?, ?, ?, ?)
                    """, connector.connectorId(), overallStatus, java.sql.Timestamp.from(checkedAt),
                    java.sql.Timestamp.from(now), json);
        }
        jdbc.update("UPDATE pathguard_connectors SET last_seen_at = ? WHERE connector_id = ? AND tenant_id = ?",
                java.sql.Timestamp.from(now), connector.connectorId(), connector.tenantId());
        return new HeartbeatAccepted(connector.connectorId(), true, now, true);
    }

    public ConnectionStatus status(UUID tenantId, UUID connectorId) {
        List<ConnectionStatus> rows = jdbc.query("""
                SELECT c.connector_id, c.connector_type, c.connection_id, c.site_id, c.zone_id,
                       c.last_seen_at, c.revoked_at, h.overall_status, h.checked_at, h.received_at,
                       h.source_checks AS source_checks
                  FROM pathguard_connectors c
                  LEFT JOIN pathguard_site_connector_heartbeats h ON h.connector_id = c.connector_id
                 WHERE c.connector_id = ? AND c.tenant_id = ?
                """, (rs, row) -> {
            String checks = rs.getString("source_checks");
            JsonNode parsed;
            try {
                parsed = checks == null ? mapper.createArrayNode() : mapper.readTree(checks);
            } catch (JsonProcessingException e) {
                throw new IllegalStateException("Stored on-prem source status is invalid JSON", e);
            }
            return new ConnectionStatus(rs.getObject("connector_id", UUID.class), rs.getString("connector_type"),
                    rs.getString("connection_id"), rs.getString("site_id"), rs.getString("zone_id"),
                    instant(rs.getTimestamp("last_seen_at")), instant(rs.getTimestamp("revoked_at")),
                    rs.getString("overall_status"), instant(rs.getTimestamp("checked_at")),
                    instant(rs.getTimestamp("received_at")), parsed);
        }, connectorId, tenantId);
        if (rows.size() != 1) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Connector not found");
        return rows.getFirst();
    }

    private static Instant instant(java.sql.Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    public record HeartbeatAccepted(UUID connectorId, boolean accepted, Instant receivedAt,
                                    boolean backendReachable) { }
    public record ConnectionStatus(UUID connectorId, String connectorType, String connectionId, String siteId,
                                   String zoneId, Instant lastSeenAt, Instant revokedAt, String overallStatus,
                                   Instant checkedAt, Instant receivedAt, JsonNode sources) { }
}
