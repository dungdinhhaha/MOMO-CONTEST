package io.pathguard.backend.aws;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.pathguard.backend.aws.AwsReadOnlyProbe.NetworkInventory;
import io.pathguard.backend.aws.AwsNetworkSnapshotRepository.SnapshotRow;
import io.pathguard.backend.aws.AwsNetworkSnapshotRepository.SnapshotView;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AwsNetworkSnapshotService {
    private final AwsNetworkSnapshotRepository repository;
    private final ObjectMapper mapper;

    public AwsNetworkSnapshotService(AwsNetworkSnapshotRepository repository, ObjectMapper mapper) {
        this.repository = repository;
        this.mapper = mapper;
    }

    public SnapshotSummary store(UUID tenantId, String connectionId, String accountId, String region,
                                 NetworkInventory inventory) {
        try {
            String payload = mapper.writeValueAsString(inventory);
            String counts = mapper.writeValueAsString(inventory.resourceCounts());
            String missing = mapper.writeValueAsString(inventory.uncoveredResourceTypes());
            String warnings = mapper.writeValueAsString(inventory.warnings());
            String coverage = coverage(inventory);
            UUID id = UUID.randomUUID();
            Instant collectedAt = inventory.collectedAt();
            repository.insert(new SnapshotRow(id, tenantId, connectionId, accountId, region, collectedAt,
                    coverage, inventory.resourceCount(), counts, missing, warnings, sha256(payload), payload));
            return new SnapshotSummary(id, coverage, inventory.resourceCount(), inventory.auditEvents().size(),
                    inventory.flowTraffic().size(), inventory.resourceCounts(),
                    inventory.uncoveredResourceTypes(), inventory.warnings(), collectedAt);
        } catch (Exception exception) {
            throw new IllegalStateException("Could not store AWS network inventory snapshot", exception);
        }
    }

    public AwsNetworkSnapshot getLatest(UUID tenantId, String connectionId) {
        SnapshotView view = repository.findLatest(tenantId, connectionId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "AWS inventory not found"));
        try {
            return new AwsNetworkSnapshot(view.snapshotId(), view.connectionId(), view.accountId(), view.region(),
                    view.collectedAt(), view.coverageStatus(), view.resourceCount(),
                    mapper.readTree(view.resourceCountsJson()), mapper.readTree(view.missingResourceTypesJson()),
                    mapper.readTree(view.warningsJson()), mapper.readTree(view.payloadJson()));
        } catch (Exception exception) {
            throw new IllegalStateException("Stored AWS inventory snapshot is invalid", exception);
        }
    }

    private static String coverage(NetworkInventory inventory) {
        if (!inventory.recorderFound() || !inventory.recording() || inventory.resourceCount() == 0) {
            return "UNKNOWN";
        }
        return inventory.uncoveredResourceTypes().isEmpty() && inventory.warnings().isEmpty()
                ? "COMPLETE" : "PARTIAL";
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    public record SnapshotSummary(UUID snapshotId, String coverageStatus, int resourceCount,
                                  int auditEventCount, int flowRecordCount,
                                  Map<String, Integer> resourceCounts, java.util.List<String> missingResourceTypes,
                                  java.util.List<String> warnings, Instant collectedAt) { }

    public record AwsNetworkSnapshot(UUID snapshotId, String connectionId, String accountId, String region,
                                     Instant collectedAt, String coverageStatus, int resourceCount,
                                     JsonNode resourceCounts, JsonNode missingResourceTypes, JsonNode warnings,
                                     JsonNode inventory) { }
}
