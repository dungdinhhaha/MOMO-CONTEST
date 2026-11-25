package io.pathguard.backend.evidence;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pathguard.backend.evidence.EvidenceBundleRepository.EvidenceBundleView;
import io.pathguard.backend.evidence.EvidenceBundleRepository.StoredEvidenceBundle;
import io.pathguard.backend.security.ConnectorIdentity;
import io.pathguard.backend.security.TenantIdentity;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class EvidenceBundleService {
    private final EvidenceBundleValidator validator;
    private final EvidenceBundleRepository repository;
    private final ObjectMapper objectMapper;

    public EvidenceBundleService(EvidenceBundleValidator validator,
                                 EvidenceBundleRepository repository,
                                 ObjectMapper objectMapper) {
        this.validator = validator;
        this.repository = repository;
        this.objectMapper = objectMapper;
    }

    public IngestResult ingest(byte[] body, ConnectorIdentity identity) {
        EvidenceBundleValidator.ValidatedBundle validated = validator.validate(body, identity);
        String hash = sha256(validated.normalizedJson());
        UUID bundleId = UUID.randomUUID();
        Instant receivedAt = Instant.now();
        StoredEvidenceBundle stored = new StoredEvidenceBundle(
                bundleId,
                identity.tenantId(),
                identity.connectorId(),
                identity.connectorType(),
                identity.connectionId(),
                identity.siteId(),
                identity.zoneId(),
                validated.schemaVersion(),
                validated.collectedAt(),
                receivedAt,
                validated.coverageStatus(),
                validated.recordCount(),
                hash,
                validated.normalizedJson());

        UUID persistedId = repository.insert(stored);
        return new IngestResult(persistedId, identity.connectorId(), validated.recordCount(),
                validated.coverageStatus(), receivedAt, !persistedId.equals(bundleId));
    }

    public EvidencePage list(TenantIdentity identity, Instant after, Instant before, int limit, int offset) {
        if (limit < 1 || limit > 100) {
            throw new InvalidEvidenceQueryException("limit must be between 1 and 100");
        }
        if (offset < 0 || offset > 100_000) {
            throw new InvalidEvidenceQueryException("offset must be between 0 and 100000");
        }
        if (after != null && before != null && !before.isAfter(after)) {
            throw new InvalidEvidenceQueryException("until must be later than since");
        }
        List<EvidenceBundleView> rows = repository.findByTenant(identity.tenantId(), after, before, limit, offset);
        List<EvidenceSummary> summaries = rows.stream().map(row -> new EvidenceSummary(
                row.bundleId(), row.connectorId(), row.connectorType(), row.connectionId(), row.siteId(), row.zoneId(),
                row.schemaVersion(), row.collectedAt(), row.receivedAt(), row.coverageStatus(), row.recordCount(),
                parsePayload(row.payloadJson()))).toList();
        return new EvidencePage(identity.tenantId(), summaries, limit, offset);
    }

    private Object parsePayload(String payloadJson) {
        try {
            return objectMapper.readTree(payloadJson);
        } catch (Exception exception) {
            throw new IllegalStateException("Stored evidence JSON is invalid", exception);
        }
    }

    private String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available", exception);
        }
    }

    public record IngestResult(UUID bundleId, UUID connectorId, int recordCount,
                               String coverageStatus, Instant receivedAt, boolean duplicate) {}
    public record EvidenceSummary(UUID bundleId, UUID connectorId, String connectorType,
                                 String connectionId, String siteId, String zoneId,
                                 String schemaVersion, Instant collectedAt, Instant receivedAt,
                                 String coverageStatus, int recordCount, Object payload) {}
    public record EvidencePage(UUID tenantId, List<EvidenceSummary> items, int limit, int offset) {}
}
