package io.pathguard.backend.evidence;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.ArrayList;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class EvidenceBundleRepository {
    private final JdbcTemplate jdbcTemplate;

    public EvidenceBundleRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public UUID insert(StoredEvidenceBundle bundle) {
        try {
            jdbcTemplate.update("""
                    INSERT INTO pathguard_evidence_bundle (
                        bundle_id, tenant_id, connector_id, connector_type, connection_id,
                        site_id, zone_id, schema_version, collected_at, received_at,
                        coverage_status, record_count, payload_sha256, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    bundle.bundleId(), bundle.tenantId(), bundle.connectorId(), bundle.connectorType(),
                    bundle.connectionId(), bundle.siteId(), bundle.zoneId(), bundle.schemaVersion(),
                    Timestamp.from(bundle.collectedAt()), Timestamp.from(bundle.receivedAt()),
                    bundle.coverageStatus(), bundle.recordCount(), bundle.payloadSha256(), bundle.payloadJson());
            return bundle.bundleId();
        } catch (DuplicateKeyException duplicate) {
            return findDuplicateId(bundle.tenantId(), bundle.connectorId(), bundle.payloadSha256())
                    .orElseThrow(() -> duplicate);
        }
    }

    private Optional<UUID> findDuplicateId(UUID tenantId, UUID connectorId, String payloadSha256) {
        List<UUID> ids = jdbcTemplate.query(
                "SELECT bundle_id FROM pathguard_evidence_bundle "
                        + "WHERE tenant_id = ? AND connector_id = ? AND payload_sha256 = ?",
                (rs, rowNum) -> rs.getObject("bundle_id", UUID.class), tenantId, connectorId, payloadSha256);
        return ids.stream().findFirst();
    }

    public List<EvidenceBundleView> findByTenant(UUID tenantId, Instant after, Instant before, int limit, int offset) {
        StringBuilder sql = new StringBuilder("SELECT bundle_id, connector_id, connector_type, connection_id, "
                + "site_id, zone_id, schema_version, collected_at, received_at, coverage_status, "
                + "record_count, payload_json FROM pathguard_evidence_bundle WHERE tenant_id = ?");
        List<Object> parameters = new ArrayList<>();
        parameters.add(tenantId);
        if (after != null) {
            sql.append(" AND received_at >= ?");
            parameters.add(Timestamp.from(after));
        }
        if (before != null) {
            sql.append(" AND received_at <= ?");
            parameters.add(Timestamp.from(before));
        }
        sql.append(" ORDER BY received_at DESC, bundle_id LIMIT ? OFFSET ?");
        parameters.add(limit);
        parameters.add(offset);
        return jdbcTemplate.query(sql.toString(), this::mapView, parameters.toArray());
    }

    private EvidenceBundleView mapView(ResultSet rs, int rowNum) throws SQLException {
        return new EvidenceBundleView(
                rs.getObject("bundle_id", UUID.class),
                rs.getObject("connector_id", UUID.class),
                rs.getString("connector_type"),
                rs.getString("connection_id"), rs.getString("site_id"), rs.getString("zone_id"),
                rs.getString("schema_version"), rs.getTimestamp("collected_at").toInstant(),
                rs.getTimestamp("received_at").toInstant(), rs.getString("coverage_status"),
                rs.getInt("record_count"), rs.getString("payload_json"));
    }

    public record StoredEvidenceBundle(
            UUID bundleId, UUID tenantId, UUID connectorId, String connectorType,
            String connectionId, String siteId, String zoneId, String schemaVersion,
            Instant collectedAt, Instant receivedAt, String coverageStatus,
            int recordCount, String payloadSha256, String payloadJson
    ) {}

    public record EvidenceBundleView(
            UUID bundleId, UUID connectorId, String connectorType,
            String connectionId, String siteId, String zoneId, String schemaVersion,
            Instant collectedAt, Instant receivedAt, String coverageStatus,
            int recordCount, String payloadJson
    ) {}
}
