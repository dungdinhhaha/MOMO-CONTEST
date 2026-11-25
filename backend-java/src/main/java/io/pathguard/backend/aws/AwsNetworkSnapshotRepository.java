package io.pathguard.backend.aws;

import com.fasterxml.jackson.databind.JsonNode;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class AwsNetworkSnapshotRepository {
    private final JdbcTemplate jdbc;

    public AwsNetworkSnapshotRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public UUID insert(SnapshotRow row) {
        jdbc.update("""
                INSERT INTO pathguard_aws_network_snapshot (
                    snapshot_id, tenant_id, connection_id, account_id, region, collected_at,
                    coverage_status, resource_count, resource_counts, missing_resource_types,
                    warnings, payload_sha256, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?::json, ?::json, ?::json, ?, ?::json)
                """, row.snapshotId(), row.tenantId(), row.connectionId(), row.accountId(), row.region(),
                Timestamp.from(row.collectedAt()), row.coverageStatus(), row.resourceCount(),
                row.resourceCountsJson(), row.missingResourceTypesJson(), row.warningsJson(),
                row.payloadSha256(), row.payloadJson());
        return row.snapshotId();
    }

    public Optional<SnapshotView> findLatest(UUID tenantId, String connectionId) {
        List<SnapshotView> rows = jdbc.query("""
                SELECT snapshot_id, connection_id, account_id, region, collected_at, coverage_status,
                       resource_count, CAST(resource_counts AS VARCHAR) AS resource_counts,
                       CAST(missing_resource_types AS VARCHAR) AS missing_resource_types,
                       CAST(warnings AS VARCHAR) AS warnings, CAST(payload_json AS VARCHAR) AS payload_json
                  FROM pathguard_aws_network_snapshot
                 WHERE tenant_id = ? AND connection_id = ?
                 ORDER BY collected_at DESC, snapshot_id DESC
                 LIMIT 1
                """, this::map, tenantId, connectionId);
        return rows.stream().findFirst();
    }

    private SnapshotView map(ResultSet rs, int rowNum) throws SQLException {
        return new SnapshotView(rs.getObject("snapshot_id", UUID.class), rs.getString("connection_id"),
                rs.getString("account_id"), rs.getString("region"), rs.getTimestamp("collected_at").toInstant(),
                rs.getString("coverage_status"), rs.getInt("resource_count"), rs.getString("resource_counts"),
                rs.getString("missing_resource_types"), rs.getString("warnings"), rs.getString("payload_json"));
    }

    public record SnapshotRow(UUID snapshotId, UUID tenantId, String connectionId, String accountId, String region,
                              Instant collectedAt, String coverageStatus, int resourceCount,
                              String resourceCountsJson, String missingResourceTypesJson, String warningsJson,
                              String payloadSha256, String payloadJson) { }

    public record SnapshotView(UUID snapshotId, String connectionId, String accountId, String region,
                              Instant collectedAt, String coverageStatus, int resourceCount,
                              String resourceCountsJson, String missingResourceTypesJson, String warningsJson,
                              String payloadJson) { }
}
