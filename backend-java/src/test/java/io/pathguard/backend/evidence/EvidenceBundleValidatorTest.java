package io.pathguard.backend.evidence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.pathguard.backend.security.ConnectorIdentity;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EvidenceBundleValidatorTest {
    private final UUID tenantId = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private final UUID connectorId = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private EvidenceBundleValidator validator;
    private ConnectorIdentity connector;

    @BeforeEach
    void setUp() {
        validator = new EvidenceBundleValidator(new ObjectMapper());
        connector = new ConnectorIdentity(tenantId, connectorId, "AWS", "aws-prod", null, null);
    }

    @Test
    void acceptsBoundedVersionedBundle() {
        var result = validator.validate(validBundle().getBytes(StandardCharsets.UTF_8), connector);

        assertEquals("pathguard.evidence-bundle.v1", result.schemaVersion());
        assertEquals(1, result.recordCount());
        assertEquals("complete", result.coverageStatus());
    }

    @Test
    void cicdBundleRequiresMatchingConnectorIdentity() {
        ConnectorIdentity cicd = new ConnectorIdentity(tenantId, connectorId, "CI_CD", "github-wallet-prod", null, null);
        String payload = validBundle().replace("\"source_type\":\"AWS\"", "\"source_type\":\"CI_CD\"")
                .replace("aws-prod", "github-wallet-prod");
        assertEquals(1, validator.validate(payload.getBytes(StandardCharsets.UTF_8), cicd).recordCount());
        assertThrows(InvalidEvidenceBundleException.class,
                () -> validator.validate(payload.getBytes(StandardCharsets.UTF_8), connector));
    }

    @Test
    void rejectsClientTenantClaim() {
        String payload = validBundle().replace("\"source_type\":\"AWS\",", "\"tenant_id\":\"victim\",\"source_type\":\"AWS\",");
        assertThrows(InvalidEvidenceBundleException.class,
                () -> validator.validate(payload.getBytes(StandardCharsets.UTF_8), connector));
    }

    @Test
    void rejectsNestedTenantClaim() {
        String payload = validBundle().replace("\"payload\":{}", "\"payload\":{\"tenantId\":\"victim\"}");
        assertThrows(InvalidEvidenceBundleException.class,
                () -> validator.validate(payload.getBytes(StandardCharsets.UTF_8), connector));
    }

    @Test
    void rejectsMismatchedConnectionReference() {
        String payload = validBundle().replace("aws-prod", "somebody-elses-connection");
        assertThrows(InvalidEvidenceBundleException.class,
                () -> validator.validate(payload.getBytes(StandardCharsets.UTF_8), connector));
    }

    @Test
    void rejectsCredentialLikeFieldsInsteadOfPersistingThem() {
        String payload = validBundle().replace("\"payload\":{}", "\"payload\":{\"client_secret\":\"do-not-store\"}");
        assertThrows(InvalidEvidenceBundleException.class,
                () -> validator.validate(payload.getBytes(StandardCharsets.UTF_8), connector));
    }

    @Test
    void rejectsDuplicateEvidenceIds() {
        String record = "{\"id\":\"r1\",\"evidence_type\":\"config\",\"resource_key\":\"acct/region/vpc-1\","
                + "\"observed_at\":\"2026-11-24T10:00:00Z\",\"payload\":{}}";
        String payload = "{\"schema_version\":\"pathguard.evidence-bundle.v1\","
                + "\"collected_at\":\"2026-11-24T10:01:00Z\",\"source_type\":\"aws\","
                + "\"connection_id\":\"aws-prod\",\"records\":[" + record + "," + record + "],"
                + "\"coverage\":{\"status\":\"complete\",\"window_start\":\"2026-11-24T09:00:00Z\","
                + "\"window_end\":\"2026-11-24T10:00:00Z\"}}";
        assertThrows(InvalidEvidenceBundleException.class,
                () -> validator.validate(payload.getBytes(StandardCharsets.UTF_8), connector));
    }

    @Test
    void rejectsOversizedBundleBeforeParsing() {
        byte[] payload = new byte[EvidenceBundleValidator.MAX_BUNDLE_BYTES + 1];
        assertThrows(InvalidEvidenceBundleException.class, () -> validator.validate(payload, connector));
    }

    private String validBundle() {
        return "{\"schema_version\":\"pathguard.evidence-bundle.v1\","
                + "\"collected_at\":\"2026-11-24T10:01:00Z\",\"source_type\":\"AWS\","
                + "\"connection_id\":\"aws-prod\",\"records\":[{\"id\":\"r1\","
                + "\"evidence_type\":\"config\",\"resource_key\":\"acct/region/vpc-1\","
                + "\"observed_at\":\"2026-11-24T10:00:00Z\",\"payload\":{}}],"
                + "\"coverage\":{\"status\":\"complete\",\"window_start\":\"2026-11-24T09:00:00Z\","
                + "\"window_end\":\"2026-11-24T10:00:00Z\"}}";
    }
}
