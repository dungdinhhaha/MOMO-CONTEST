package io.pathguard.backend.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class AwsConnectionServiceTest {
    private static final UUID TENANT = UUID.randomUUID();
    private static final AwsConnectionService.ConnectionTestRequest VALID =
            new AwsConnectionService.ConnectionTestRequest(
                    "momo-prod", "arn:aws:iam::123456789012:role/PathGuardReadOnly",
                    "123456789012", "ap-southeast-1");
    private static final String EXTERNAL_ID = "pg-tenant-derived-test-id";

    @Test
    void externalIdDerivationIsStableAndTenantScoped() {
        var externalIds = new AwsExternalIdService("test-signing-key-with-at-least-32-bytes-long");
        String tenantA = externalIds.derive(TENANT, "momo-prod");
        String tenantARepeat = externalIds.derive(TENANT, "momo-prod");
        String tenantB = externalIds.derive(UUID.randomUUID(), "momo-prod");
        assertEquals(tenantA, tenantARepeat);
        assertFalse(tenantA.equals(tenantB));
        assertTrue(tenantA.startsWith("pg-"));
    }

    @Test
    void successfulInventoryProbePersistsTenantSnapshotAndReportsCoverage() {
        AwsReadOnlyProbe probe = mock(AwsReadOnlyProbe.class);
        AwsNetworkSnapshotService snapshots = mock(AwsNetworkSnapshotService.class);
        var inventory = new AwsReadOnlyProbe.NetworkInventory(Instant.now(), true, true, true,
                List.of("AWS::EC2::VPC"), List.of("AWS::EC2::FlowLog"), Map.of("AWS::EC2::VPC", 1),
                List.of(new AwsReadOnlyProbe.NetworkResource("AWS::EC2::VPC", "vpc-123", "lab-vpc",
                        "123456789012", "ap-southeast-1", null, List.of())), List.of(), List.of(),
                List.of("NOT_RECORDED_AWS_EC2_FlowLog"));
        when(probe.probe(VALID.roleArn(), EXTERNAL_ID, VALID.expectedAccountId(), VALID.region(), TENANT))
                .thenReturn(new AwsReadOnlyProbe.ProbeResult(true, true, "123456789012",
                        "arn:aws:sts::123456789012:assumed-role/PathGuardReadOnly/session", inventory,
                        "AWS_ROLE_AND_NETWORK_INVENTORY_READABLE"));
        var snapshotId = UUID.randomUUID();
        when(snapshots.store(TENANT, "momo-prod", "123456789012", "ap-southeast-1", inventory))
                .thenReturn(new AwsNetworkSnapshotService.SnapshotSummary(snapshotId, "PARTIAL", 1, 3, 4,
                        Map.of("AWS::EC2::VPC", 1), List.of("AWS::EC2::FlowLog"),
                        List.of("NOT_RECORDED_AWS_EC2_FlowLog"), inventory.collectedAt()));

        var result = new AwsConnectionService(probe, snapshots).testConnection(TENANT, VALID, EXTERNAL_ID);

        assertTrue(result.identityVerified());
        assertTrue(result.configApiReachable());
        assertEquals(1, result.resourceCount());
        assertEquals("PARTIAL", result.coverageStatus());
        assertEquals(snapshotId, result.snapshotId());
        assertEquals(List.of("AWS::EC2::FlowLog"), result.missingResourceTypes());
        assertTrue(result.connectionReady());
        assertFalse(result.toString().contains(EXTERNAL_ID));
    }

    @Test
    void roleArnCannotTargetDifferentAccountThanExpected() {
        AwsReadOnlyProbe probe = mock(AwsReadOnlyProbe.class);
        var service = new AwsConnectionService(probe, mock(AwsNetworkSnapshotService.class));
        var mismatch = new AwsConnectionService.ConnectionTestRequest(
                VALID.connectionId(), VALID.roleArn(), "000000000001", VALID.region());
        var error = assertThrows(ResponseStatusException.class,
                () -> service.testConnection(TENANT, mismatch, EXTERNAL_ID));
        assertEquals(400, error.getStatusCode().value());
        verifyNoInteractions(probe);
    }

    @Test
    void malformedRoleArnDoesNotCallProbe() {
        AwsReadOnlyProbe probe = mock(AwsReadOnlyProbe.class);
        var bad = new AwsConnectionService.ConnectionTestRequest(
                VALID.connectionId(), "http://169.254.169.254/latest/meta-data/",
                VALID.expectedAccountId(), VALID.region());
        var error = assertThrows(ResponseStatusException.class,
                () -> new AwsConnectionService(probe, mock(AwsNetworkSnapshotService.class))
                        .testConnection(TENANT, bad, EXTERNAL_ID));
        assertEquals(400, error.getStatusCode().value());
        verifyNoInteractions(probe);
    }

    @Test
    void configReadFailureDoesNotPersistSnapshotOrClaimReady() {
        AwsReadOnlyProbe probe = mock(AwsReadOnlyProbe.class);
        AwsNetworkSnapshotService snapshots = mock(AwsNetworkSnapshotService.class);
        when(probe.probe(any(), any(), any(), any(), any()))
                .thenReturn(new AwsReadOnlyProbe.ProbeResult(true, false, "123456789012", "assumed-role",
                        null, "AWS_CONFIG_READ_FAILED"));
        var result = new AwsConnectionService(probe, snapshots).testConnection(TENANT, VALID, EXTERNAL_ID);
        assertTrue(result.identityVerified());
        assertFalse(result.configApiReachable());
        assertFalse(result.connectionReady());
        assertEquals("AWS_CONFIG_READ_FAILED", result.resultCode());
        assertEquals("UNKNOWN", result.coverageStatus());
    }
}
