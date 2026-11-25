package io.pathguard.backend.aws;

import java.util.UUID;
import java.time.Duration;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.config.ConfigClient;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.cloudtrail.CloudTrailClient;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsClient;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;

/** Calls STS and AWS Config using the backend workload identity and short-lived assumed-role credentials. */
@Component
public class SdkAwsReadOnlyProbe implements AwsReadOnlyProbe {
    private static final Pattern ACCOUNT = Pattern.compile("^[0-9]{12}$");
    private static final ClientOverrideConfiguration CALL_TIMEOUTS = ClientOverrideConfiguration.builder()
            .apiCallTimeout(Duration.ofSeconds(90))
            .apiCallAttemptTimeout(Duration.ofSeconds(12))
            .build();

    private final AwsConfigNetworkCollector collector;
    private final AwsOperationalEvidenceCollector evidenceCollector;

    public SdkAwsReadOnlyProbe(AwsConfigNetworkCollector collector,
                               AwsOperationalEvidenceCollector evidenceCollector) {
        this.collector = collector;
        this.evidenceCollector = evidenceCollector;
    }

    @Override
    public ProbeResult probe(String roleArn, String externalId, String expectedAccountId, String region,
                             UUID tenantId) {
        try (StsClient sts = StsClient.builder().region(Region.of(region))
                .overrideConfiguration(CALL_TIMEOUTS).build()) {
            var assumed = sts.assumeRole(AssumeRoleRequest.builder()
                    .roleArn(roleArn)
                    .roleSessionName("pg-" + tenantId.toString().substring(0, 8) + "-" + UUID.randomUUID())
                    .externalId(externalId)
                    .durationSeconds(900)
                    .build());
            var credentials = assumed.credentials();
            var provider = StaticCredentialsProvider.create(AwsSessionCredentials.create(
                    credentials.accessKeyId(), credentials.secretAccessKey(), credentials.sessionToken()));

            try (StsClient assumedSts = StsClient.builder().region(Region.of(region))
                    .credentialsProvider(provider).overrideConfiguration(CALL_TIMEOUTS).build()) {
                var identity = assumedSts.getCallerIdentity(GetCallerIdentityRequest.builder().build());
                String accountId = identity.account();
                String assumedArn = identity.arn();
                if (!ACCOUNT.matcher(accountId == null ? "" : accountId).matches()
                        || !expectedAccountId.equals(accountId)) {
                    return new ProbeResult(false, false, accountId, assumedArn, null, "AWS_ACCOUNT_MISMATCH");
                }

                try (ConfigClient config = ConfigClient.builder().region(Region.of(region))
                        .credentialsProvider(provider).overrideConfiguration(CALL_TIMEOUTS).build();
                     Ec2Client ec2 = Ec2Client.builder().region(Region.of(region))
                             .credentialsProvider(provider).overrideConfiguration(CALL_TIMEOUTS).build();
                     CloudTrailClient cloudTrail = CloudTrailClient.builder().region(Region.of(region))
                             .credentialsProvider(provider).overrideConfiguration(CALL_TIMEOUTS).build();
                     CloudWatchLogsClient logs = CloudWatchLogsClient.builder().region(Region.of(region))
                             .credentialsProvider(provider).overrideConfiguration(CALL_TIMEOUTS).build();
                     S3Client s3 = S3Client.builder().region(Region.of(region))
                             .credentialsProvider(provider).overrideConfiguration(CALL_TIMEOUTS).build()) {
                    var inventory = collector.collect(config, ec2, accountId, region);
                    inventory = evidenceCollector.collect(cloudTrail, logs, s3, inventory, accountId, region);
                    String resultCode = !inventory.apiReachable() ? "AWS_CONFIG_READ_FAILED"
                            : inventory.resourceCount() > 0 ? "AWS_ROLE_AND_NETWORK_INVENTORY_READABLE"
                            : !inventory.recorderFound() ? "AWS_CONFIG_RECORDER_NOT_FOUND"
                            : !inventory.recording() ? "AWS_CONFIG_RECORDER_NOT_RUNNING"
                            : "AWS_NETWORK_INVENTORY_EMPTY";
                    return new ProbeResult(true, inventory.apiReachable(), accountId, assumedArn,
                            inventory, resultCode);
                } catch (RuntimeException configFailure) {
                    // Deliberately omit the AWS message, which can contain customer identifiers.
                    return new ProbeResult(true, false, accountId, assumedArn, null, "AWS_CONFIG_READ_FAILED");
                }
            } catch (RuntimeException identityFailure) {
                return new ProbeResult(false, false, null, null, null, "AWS_IDENTITY_VERIFY_FAILED");
            }
        } catch (RuntimeException assumeRoleFailure) {
            // Deliberately omit the AWS message and request parameters from the response/logs.
            return new ProbeResult(false, false, null, null, null, "AWS_ASSUME_ROLE_FAILED");
        }
    }
}
