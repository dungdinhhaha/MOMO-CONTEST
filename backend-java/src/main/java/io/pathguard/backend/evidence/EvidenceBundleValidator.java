package io.pathguard.backend.evidence;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.pathguard.backend.security.ConnectorIdentity;
import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class EvidenceBundleValidator {
    public static final int MAX_BUNDLE_BYTES = 2 * 1024 * 1024;
    public static final int MAX_RECORDS = 5_000;
    private static final Pattern SECRET_FIELD = Pattern.compile(
            "(?i).*(password|passwd|secret|credential|authorization|api.?key|access.?key|private.?key|(^|_)token($|_)).*"
    );
    private final ObjectMapper objectMapper;

    public EvidenceBundleValidator(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public ValidatedBundle validate(byte[] body, ConnectorIdentity identity) {
        if (body == null || body.length == 0 || body.length > MAX_BUNDLE_BYTES) {
            throw new InvalidEvidenceBundleException("Bundle must be between 1 byte and 2 MiB");
        }

        final JsonNode root;
        try {
            root = objectMapper.readTree(body);
        } catch (IOException exception) {
            throw new InvalidEvidenceBundleException("Bundle must be valid JSON");
        }
        if (root == null || !root.isObject()) {
            throw new InvalidEvidenceBundleException("Bundle root must be a JSON object");
        }
        if (containsTenantClaim(root)) {
            throw new InvalidEvidenceBundleException("Client tenant_id is not accepted");
        }
        rejectSecretFields(root, "bundle");

        String schemaVersion = requiredText(root, "schema_version");
        if (!"pathguard.evidence-bundle.v1".equals(schemaVersion)) {
            throw new InvalidEvidenceBundleException("Unsupported evidence bundle schema_version");
        }
        Instant collectedAt = requiredInstant(root, "collected_at");
        validateOptionalRef(root, "connector_id", identity.connectorId().toString());
        validateOptionalRef(root, "connection_id", identity.connectionId());
        validateOptionalRef(root, "site_id", identity.siteId());
        validateOptionalRef(root, "zone_id", identity.zoneId());
        if (root.hasNonNull("source_type")
                && !identity.connectorType().equalsIgnoreCase(root.path("source_type").asText())) {
            throw new InvalidEvidenceBundleException("source_type does not match authenticated connector");
        }
        if (!root.hasNonNull("source_type")) {
            throw new InvalidEvidenceBundleException("source_type is required");
        }

        JsonNode records = root.get("records");
        if (records == null || !records.isArray() || records.isEmpty() || records.size() > MAX_RECORDS) {
            throw new InvalidEvidenceBundleException("records must contain between 1 and 5000 items");
        }
        Set<String> recordIds = new HashSet<>();
        for (JsonNode record : records) {
            if (!record.isObject()) {
                throw new InvalidEvidenceBundleException("Each record must be an object");
            }
            String id = requiredText(record, "id");
            if (id.length() > 256 || !recordIds.add(id)) {
                throw new InvalidEvidenceBundleException("Record IDs must be unique and at most 256 characters");
            }
            requiredText(record, "evidence_type");
            requiredText(record, "resource_key");
            requiredInstant(record, "observed_at");
            if (!record.has("payload") || !record.get("payload").isObject()) {
                throw new InvalidEvidenceBundleException("Each record requires an object payload");
            }
        }

        JsonNode coverage = root.get("coverage");
        if (coverage == null || !coverage.isObject()) {
            throw new InvalidEvidenceBundleException("coverage must be an object");
        }
        String coverageStatus = requiredText(coverage, "status");
        if (!Set.of("complete", "partial", "unknown").contains(coverageStatus)) {
            throw new InvalidEvidenceBundleException("coverage.status must be complete, partial, or unknown");
        }
        Instant windowStart = requiredInstant(coverage, "window_start");
        Instant windowEnd = requiredInstant(coverage, "window_end");
        if (!windowEnd.isAfter(windowStart) || windowEnd.isAfter(collectedAt.plusSeconds(300))) {
            throw new InvalidEvidenceBundleException("coverage time window is invalid");
        }

        try {
            String normalized = objectMapper.writeValueAsString(root);
            return new ValidatedBundle(schemaVersion, collectedAt, coverageStatus, records.size(), normalized);
        } catch (JsonProcessingException exception) {
            throw new InvalidEvidenceBundleException("Bundle could not be normalized");
        }
    }

    private void validateOptionalRef(JsonNode root, String field, String authenticatedValue) {
        if (root.hasNonNull(field)) {
            String supplied = root.path(field).asText();
            if (supplied.isBlank() || supplied.length() > 128
                    || authenticatedValue == null || !authenticatedValue.equals(supplied)) {
                throw new InvalidEvidenceBundleException(field + " does not match authenticated connector scope");
            }
        }
    }

    private boolean containsTenantClaim(JsonNode node) {
        if (node.isObject()) {
            var fields = node.fields();
            while (fields.hasNext()) {
                var entry = fields.next();
                String name = entry.getKey();
                if (name.equalsIgnoreCase("tenant_id") || name.equalsIgnoreCase("tenantId")) {
                    return true;
                }
                if (containsTenantClaim(entry.getValue())) {
                    return true;
                }
            }
        } else if (node.isArray()) {
            for (JsonNode item : node) {
                if (containsTenantClaim(item)) {
                    return true;
                }
            }
        }
        return false;
    }

    private String requiredText(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.isTextual() || value.asText().isBlank()) {
            throw new InvalidEvidenceBundleException(field + " is required");
        }
        return value.asText();
    }

    private Instant requiredInstant(JsonNode node, String field) {
        try {
            return Instant.parse(requiredText(node, field));
        } catch (DateTimeParseException exception) {
            throw new InvalidEvidenceBundleException(field + " must be an ISO-8601 UTC timestamp");
        }
    }

    private void rejectSecretFields(JsonNode node, String path) {
        if (node.isObject()) {
            var fields = node.fields();
            while (fields.hasNext()) {
                var entry = fields.next();
                if (SECRET_FIELD.matcher(entry.getKey()).matches()) {
                    throw new InvalidEvidenceBundleException("Sensitive field rejected at " + path);
                }
                rejectSecretFields(entry.getValue(), path + "." + entry.getKey());
            }
        } else if (node.isArray()) {
            for (int index = 0; index < node.size(); index++) {
                rejectSecretFields(node.get(index), path + "[" + index + "]");
            }
        }
    }

    public record ValidatedBundle(
            String schemaVersion,
            Instant collectedAt,
            String coverageStatus,
            int recordCount,
            String normalizedJson
    ) {}
}
