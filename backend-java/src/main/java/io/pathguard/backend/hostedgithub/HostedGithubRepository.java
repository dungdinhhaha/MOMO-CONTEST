package io.pathguard.backend.hostedgithub;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class HostedGithubRepository {
    private final JdbcTemplate jdbc;

    public HostedGithubRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public int countForTenant(UUID tenantId) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM pathguard_hosted_github_source "
                + "WHERE tenant_id = ? AND enabled = TRUE", Integer.class, tenantId);
    }

    public void insert(Source row, String unusedCredentialHash) {
        jdbc.update("""
                INSERT INTO pathguard_connectors (connector_id, tenant_id, connector_type, connection_id,
                    credential_hash, created_by, created_at, expires_at)
                VALUES (?, ?, 'CI_CD', ?, ?, ?, ?, ?)
                """, row.sourceId(), row.tenantId(), row.connectionId(), unusedCredentialHash,
                row.createdBy(), Timestamp.from(row.createdAt()),
                Timestamp.from(Instant.parse("2100-01-01T00:00:00Z")));
        jdbc.update("""
                INSERT INTO pathguard_hosted_github_source (source_id, tenant_id, repository,
                    workflow_name, service_name, environment_name, connection_id,
                    created_by, created_at, next_poll_at, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, TRUE)
                """, row.sourceId(), row.tenantId(), row.repository(), row.workflowName(),
                row.serviceName(), row.environmentName(), row.connectionId(), row.createdBy(),
                Timestamp.from(row.createdAt()), Timestamp.from(row.createdAt()));
    }

    public List<Source> list(UUID tenantId) {
        return jdbc.query("SELECT * FROM pathguard_hosted_github_source WHERE tenant_id = ? "
                        + "ORDER BY created_at DESC LIMIT 20", (rs, index) -> map(rs), tenantId);
    }

    public Source find(UUID tenantId, UUID sourceId) {
        return jdbc.query("SELECT * FROM pathguard_hosted_github_source "
                        + "WHERE tenant_id = ? AND source_id = ?", (rs, index) -> map(rs),
                tenantId, sourceId).stream().findFirst().orElse(null);
    }

    public List<Source> due(int limit) {
        return jdbc.query("SELECT * FROM pathguard_hosted_github_source WHERE enabled = TRUE "
                        + "AND next_poll_at <= CURRENT_TIMESTAMP ORDER BY next_poll_at LIMIT ?",
                (rs, index) -> map(rs), limit);
    }

    public boolean claim(Source row, Instant now) {
        return jdbc.update("UPDATE pathguard_hosted_github_source SET next_poll_at = ? "
                        + "WHERE source_id = ? AND enabled = TRUE AND next_poll_at <= ?",
                Timestamp.from(now.plusSeconds(300)), row.sourceId(), Timestamp.from(now)) == 1;
    }

    public void success(UUID sourceId, Instant now) {
        jdbc.update("UPDATE pathguard_hosted_github_source SET last_success_at = ?, "
                        + "last_error_code = NULL WHERE source_id = ? AND enabled = TRUE",
                Timestamp.from(now), sourceId);
    }

    public void error(UUID sourceId, String code) {
        jdbc.update("UPDATE pathguard_hosted_github_source SET last_error_code = ? "
                + "WHERE source_id = ? AND enabled = TRUE", code, sourceId);
    }

    public boolean disable(UUID tenantId, UUID sourceId) {
        int changed = jdbc.update("UPDATE pathguard_hosted_github_source SET enabled = FALSE "
                + "WHERE tenant_id = ? AND source_id = ? AND enabled = TRUE", tenantId, sourceId);
        if (changed == 1) {
            jdbc.update("UPDATE pathguard_connectors SET revoked_at = CURRENT_TIMESTAMP "
                    + "WHERE tenant_id = ? AND connector_id = ?", tenantId, sourceId);
        }
        return changed == 1;
    }

    private Source map(java.sql.ResultSet rs) throws java.sql.SQLException {
        var last = rs.getTimestamp("last_success_at");
        return new Source(rs.getObject("source_id", UUID.class), rs.getObject("tenant_id", UUID.class),
                rs.getString("repository"), rs.getString("workflow_name"),
                rs.getString("service_name"), rs.getString("environment_name"),
                rs.getString("connection_id"), rs.getString("created_by"),
                rs.getTimestamp("created_at").toInstant(),
                last == null ? null : last.toInstant(), rs.getString("last_error_code"),
                rs.getBoolean("enabled"));
    }

    public record Source(UUID sourceId, UUID tenantId, String repository,
                         String workflowName, String serviceName, String environmentName,
                         String connectionId, String createdBy, Instant createdAt,
                         Instant lastSuccessAt, String lastErrorCode, boolean enabled) {}
}
