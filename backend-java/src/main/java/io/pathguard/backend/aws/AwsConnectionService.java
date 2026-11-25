package io.pathguard.backend.aws;

import java.util.UUID;
import java.time.Instant;
import java.util.regex.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AwsConnectionService {
    private static final Pattern ROLE_ARN = Pattern.compile(
            "^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$");
    private static final Pattern ACCOUNT_ID = Pattern.compile("^[0-9]{12}$");
    private static final Pattern REGION = Pattern.compile("^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$");

    private final AwsReadOnlyProbe probe;
    private final AwsNetworkSnapshotService snapshots;

    public AwsConnectionService(AwsReadOnlyProbe probe, AwsNetworkSnapshotService snapshots) {
        this.probe = probe;
        this.snapshots = snapshots;
    }

    public ConnectionTestResult testConnection(UUID tenantId, ConnectionTestRequest request, String externalId) {
        if (tenantId == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Verified tenant identity is required");
        }
        validate(request);
        Instant testedAt = Instant.now();
        try {
            AwsReadOnlyProbe.ProbeResult result = probe.probe(
                    request.roleArn(), externalId, request.expectedAccountId(), request.region(), tenantId);
            AwsNetworkSnapshotService.SnapshotSummary snapshot = null;
            if (result.identityVerified() && result.configApiReachable() && result.inventory() != null) {
                snapshot = snapshots.store(tenantId, request.connectionId(), result.accountId(),
                        request.region(), result.inventory());
            }
            int resourceCount = snapshot == null ? 0 : snapshot.resourceCount();
            return new ConnectionTestResult(
                    result.identityVerified(), result.configApiReachable(),
                    result.accountId(), result.assumedRoleArn(), resourceCount,
                    snapshot == null ? 0 : snapshot.auditEventCount(),
                    snapshot == null ? 0 : snapshot.flowRecordCount(),
                    result.identityVerified() && result.configApiReachable() && resourceCount > 0,
                    snapshot == null ? "UNKNOWN" : snapshot.coverageStatus(),
                    snapshot == null ? null : snapshot.snapshotId(),
                    snapshot == null ? java.util.Map.of() : snapshot.resourceCounts(),
                    snapshot == null ? java.util.List.of() : snapshot.missingResourceTypes(),
                    snapshot == null ? java.util.List.of() : snapshot.warnings(),
                    result.resultCode(), testedAt);
        } catch (RuntimeException exception) {
            // Keep provider messages and request values out of responses and logs.
            return new ConnectionTestResult(false, false, null, null, 0,
                    0, 0,
                    false, "UNKNOWN", null, java.util.Map.of(), java.util.List.of(), java.util.List.of(),
                    "AWS_PROBE_INTERNAL_ERROR", testedAt);
        }
    }

    private static void validate(ConnectionTestRequest request) {
        if (request == null || request.roleArn() == null || !ROLE_ARN.matcher(request.roleArn()).matches()) {
            throw badRequest("roleArn must be an IAM role ARN");
        }
        if (request.expectedAccountId() == null || !ACCOUNT_ID.matcher(request.expectedAccountId()).matches()) {
            throw badRequest("expectedAccountId must be a 12-digit AWS account ID");
        }
        if (!request.roleArn().contains(":" + request.expectedAccountId() + ":role/")) {
            throw badRequest("roleArn account must match expectedAccountId");
        }
        if (request.region() == null || !REGION.matcher(request.region()).matches()) {
            throw badRequest("region must be an AWS region identifier");
        }
    }

    private static ResponseStatusException badRequest(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }

    public record ConnectionTestRequest(String connectionId, String roleArn, String expectedAccountId,
                                        String region) { }

    public record ConnectionTestResult(boolean identityVerified, boolean configApiReachable,
                                       String accountId, String assumedRoleArn, int resourceCount,
                                       int auditEventCount, int flowRecordCount,
                                       boolean connectionReady, String coverageStatus, java.util.UUID snapshotId,
                                       java.util.Map<String, Integer> resourceCounts,
                                       java.util.List<String> missingResourceTypes, java.util.List<String> warnings,
                                       String resultCode, Instant testedAt) { }
}
