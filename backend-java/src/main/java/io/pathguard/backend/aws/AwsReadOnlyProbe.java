package io.pathguard.backend.aws;

import java.util.UUID;
import java.util.List;
import java.util.Map;
import java.time.Instant;
import com.fasterxml.jackson.databind.JsonNode;

/** Narrow seam so connection tests can prove behavior without making network calls. */
public interface AwsReadOnlyProbe {
    ProbeResult probe(String roleArn, String externalId, String expectedAccountId, String region,
                      UUID tenantId);

    record ProbeResult(boolean identityVerified, boolean configApiReachable, String accountId,
                       String assumedRoleArn, NetworkInventory inventory, String resultCode) { }

    record NetworkInventory(Instant collectedAt, boolean apiReachable, boolean recorderFound, boolean recording,
                            List<String> recordedResourceTypes, List<String> uncoveredResourceTypes,
                            Map<String, Integer> resourceCounts, List<NetworkResource> resources,
                            List<AuditEvent> auditEvents, List<FlowTraffic> flowTraffic,
                            List<String> warnings) {
        public int resourceCount() {
            return resources == null ? 0 : resources.size();
        }
    }

    record NetworkResource(String resourceType, String resourceId, String resourceName,
                           String accountId, String region, JsonNode configuration,
                           List<NetworkRelationship> relationships) { }

    record NetworkRelationship(String resourceType, String resourceId, String resourceName) { }

    record AuditEvent(String eventId, Instant eventTime, String eventSource, String eventName,
                      String username, List<NetworkRelationship> resources) { }

    record FlowTraffic(Instant startTime, Instant endTime, String interfaceId,
                       String sourceAddress, String destinationAddress, Integer sourcePort,
                       Integer destinationPort, String protocol, Long packets, Long bytes,
                       String action, String status, String destination) { }
}
