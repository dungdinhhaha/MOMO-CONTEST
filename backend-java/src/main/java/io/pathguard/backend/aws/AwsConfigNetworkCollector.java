package io.pathguard.backend.aws;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.pathguard.backend.aws.AwsReadOnlyProbe.NetworkInventory;
import io.pathguard.backend.aws.AwsReadOnlyProbe.NetworkRelationship;
import io.pathguard.backend.aws.AwsReadOnlyProbe.NetworkResource;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.services.config.ConfigClient;
import software.amazon.awssdk.services.config.model.BatchGetResourceConfigRequest;
import software.amazon.awssdk.services.config.model.ConfigurationRecorder;
import software.amazon.awssdk.services.config.model.DescribeConfigurationRecorderStatusRequest;
import software.amazon.awssdk.services.config.model.DescribeConfigurationRecordersRequest;
import software.amazon.awssdk.services.config.model.ListDiscoveredResourcesRequest;
import software.amazon.awssdk.services.config.model.ResourceIdentifier;
import software.amazon.awssdk.services.config.model.ResourceKey;
import software.amazon.awssdk.services.ec2.Ec2Client;
import software.amazon.awssdk.services.ec2.model.DescribeFlowLogsRequest;
import software.amazon.awssdk.services.ec2.model.FlowLog;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.awscore.exception.AwsServiceException;

/** Reads the current network inventory already recorded by AWS Config; performs no configuration changes. */
@Component
public class AwsConfigNetworkCollector {
    private static final Map<String, String> REFERENCE_FIELDS = Map.ofEntries(
            Map.entry("vpcId", "AWS::EC2::VPC"),
            Map.entry("subnetId", "AWS::EC2::Subnet"),
            Map.entry("subnetIds", "AWS::EC2::Subnet"),
            Map.entry("routeTableId", "AWS::EC2::RouteTable"),
            Map.entry("networkInterfaceId", "AWS::EC2::NetworkInterface"),
            Map.entry("networkInterfaceIds", "AWS::EC2::NetworkInterface"),
            Map.entry("instanceId", "AWS::EC2::Instance"),
            Map.entry("securityGroupId", "AWS::EC2::SecurityGroup"),
            Map.entry("securityGroupIds", "AWS::EC2::SecurityGroup"),
            Map.entry("groupId", "AWS::EC2::SecurityGroup"),
            Map.entry("groupIds", "AWS::EC2::SecurityGroup"),
            Map.entry("networkAclId", "AWS::EC2::NetworkAcl"),
            Map.entry("transitGatewayId", "AWS::EC2::TransitGateway"),
            Map.entry("transitGatewayAttachmentId", "AWS::EC2::TransitGatewayAttachment"),
            Map.entry("transitGatewayRouteTableId", "AWS::EC2::TransitGatewayRouteTable"),
            Map.entry("vpcPeeringConnectionId", "AWS::EC2::VPCPeeringConnection"));
    static final List<String> NETWORK_RESOURCE_TYPES = List.of(
            "AWS::EC2::VPC",
            "AWS::EC2::Subnet",
            "AWS::EC2::RouteTable",
            "AWS::EC2::SecurityGroup",
            "AWS::EC2::NetworkAcl",
            "AWS::EC2::NetworkInterface",
            "AWS::EC2::Instance",
            "AWS::EC2::FlowLog",
            "AWS::EC2::VPCPeeringConnection",
            "AWS::EC2::TransitGateway",
            "AWS::EC2::TransitGatewayAttachment",
            "AWS::EC2::TransitGatewayRouteTable",
            "AWS::EC2::VPCEndpoint",
            "AWS::ElasticLoadBalancingV2::LoadBalancer",
            "AWS::ECS::Cluster",
            "AWS::ECS::Service",
            "AWS::EKS::Cluster");
    private static final int BATCH_SIZE = 100;
    private static final int CONFIG_READ_CONCURRENCY = 4;
    private static final Logger LOG = LoggerFactory.getLogger(AwsConfigNetworkCollector.class);

    private final ObjectMapper objectMapper;

    public AwsConfigNetworkCollector(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public NetworkInventory collect(ConfigClient config, Ec2Client ec2, String accountId, String region) {
        List<String> warnings = new ArrayList<>();
        List<ConfigurationRecorder> recorders;
        try {
            recorders = config.describeConfigurationRecorders(DescribeConfigurationRecordersRequest.builder().build())
                    .configurationRecorders();
        } catch (SdkException failure) {
            return unavailable(failureCode(failure));
        }

        Set<String> recordedTypes = new LinkedHashSet<>();
        boolean recorderFound = !recorders.isEmpty();
        for (ConfigurationRecorder recorder : recorders) {
            if (recorder.recordingGroup() != null && recorder.recordingGroup().resourceTypes() != null) {
                recorder.recordingGroup().resourceTypes().stream().map(Object::toString).forEach(recordedTypes::add);
            }
        }

        boolean recording = false;
        try {
            recording = config.describeConfigurationRecorderStatus(
                    DescribeConfigurationRecorderStatusRequest.builder().build())
                    .configurationRecordersStatus().stream().anyMatch(status -> status.recording());
        } catch (SdkException failure) {
            warnings.add("RECORDER_STATUS_" + failureCode(failure));
        }

        List<String> uncovered = new ArrayList<>(NETWORK_RESOURCE_TYPES.stream()
                .filter(type -> !recordedTypes.contains(type)).toList());
        for (String type : uncovered) {
            warnings.add("NOT_RECORDED_" + type.replace("::", "_"));
        }

        Map<String, Integer> counts = new LinkedHashMap<>();
        List<NetworkResource> resources = new ArrayList<>();
        List<String> recordedNetworkTypes = NETWORK_RESOURCE_TYPES.stream().filter(recordedTypes::contains).toList();
        long inventoryStarted = System.nanoTime();
        ExecutorService executor = Executors.newFixedThreadPool(
                Math.min(CONFIG_READ_CONCURRENCY, Math.max(1, recordedNetworkTypes.size())));
        try {
            List<CompletableFuture<ResourceTypeResult>> reads = recordedNetworkTypes.stream()
                    .map(type -> CompletableFuture.supplyAsync(
                            () -> collectResourceType(config, type, accountId, region), executor))
                    .toList();
            for (CompletableFuture<ResourceTypeResult> read : reads) {
                ResourceTypeResult result = read.join();
                if (result.count() != null) counts.put(result.type(), result.count());
                resources.addAll(result.resources());
                warnings.addAll(result.warnings());
            }
        } finally {
            executor.shutdown();
        }
        LOG.info("AWS Config network inventory finished: resourceTypes={}, resources={}, elapsedMs={}",
                recordedNetworkTypes.size(), resources.size(),
                java.time.Duration.ofNanos(System.nanoTime() - inventoryStarted).toMillis());

        try {
            List<FlowLog> flowLogs = listFlowLogs(ec2);
            counts.put("AWS::EC2::FlowLog", flowLogs.size());
            for (FlowLog flowLog : flowLogs) {
                resources.add(toFlowLogResource(flowLog, accountId, region));
            }
            uncovered.remove("AWS::EC2::FlowLog");
            warnings.remove("NOT_RECORDED_AWS_EC2_FlowLog");
            if (!recordedTypes.contains("AWS::EC2::FlowLog")) {
                warnings.add("FLOW_LOGS_READ_DIRECTLY_NOT_RECORDED_BY_CONFIG");
            }
        } catch (SdkException failure) {
            warnings.add("FLOW_LOGS_READ_FAILED_" + failureCode(failure));
        }

        return new NetworkInventory(Instant.now(), true, recorderFound, recording, List.copyOf(recordedTypes),
                List.copyOf(uncovered), Map.copyOf(counts), List.copyOf(resources), List.of(), List.of(),
                List.copyOf(warnings));
    }

    private List<ResourceIdentifier> listResources(ConfigClient config, String type) {
        List<ResourceIdentifier> result = new ArrayList<>();
        String nextToken = null;
        do {
            var request = ListDiscoveredResourcesRequest.builder()
                    .resourceType(type).includeDeletedResources(false).limit(BATCH_SIZE);
            if (nextToken != null) {
                request.nextToken(nextToken);
            }
            var page = config.listDiscoveredResources(request.build());
            result.addAll(page.resourceIdentifiers());
            nextToken = page.nextToken();
        } while (nextToken != null && !nextToken.isBlank());
        return result;
    }

    private ResourceTypeResult collectResourceType(ConfigClient config, String type, String accountId, String region) {
        List<String> typeWarnings = new ArrayList<>();
        List<NetworkResource> typeResources = new ArrayList<>();
        List<ResourceIdentifier> identifiers;
        try {
            identifiers = listResources(config, type);
        } catch (SdkException failure) {
            typeWarnings.add("LIST_FAILED_" + type.replace("::", "_") + "_" + failureCode(failure));
            return new ResourceTypeResult(type, null, List.of(), List.copyOf(typeWarnings));
        }
        for (int offset = 0; offset < identifiers.size(); offset += BATCH_SIZE) {
            int end = Math.min(offset + BATCH_SIZE, identifiers.size());
            List<ResourceKey> keys = identifiers.subList(offset, end).stream().map(this::resourceKey).toList();
            try {
                var batch = config.batchGetResourceConfig(BatchGetResourceConfigRequest.builder()
                        .resourceKeys(keys).build());
                batch.baseConfigurationItems().forEach(item -> typeResources.add(toResource(item, accountId, region)));
                if (!batch.unprocessedResourceKeys().isEmpty()) {
                    typeWarnings.add("UNPROCESSED_RESOURCES_" + type.replace("::", "_"));
                }
            } catch (SdkException failure) {
                typeWarnings.add("BATCH_FAILED_" + type.replace("::", "_") + "_" + failureCode(failure));
            }
        }
        return new ResourceTypeResult(type, identifiers.size(), List.copyOf(typeResources), List.copyOf(typeWarnings));
    }

    private record ResourceTypeResult(String type, Integer count, List<NetworkResource> resources,
                                      List<String> warnings) { }

    private List<FlowLog> listFlowLogs(Ec2Client ec2) {
        List<FlowLog> result = new ArrayList<>();
        String nextToken = null;
        do {
            var request = DescribeFlowLogsRequest.builder();
            if (nextToken != null) {
                request.nextToken(nextToken);
            }
            var page = ec2.describeFlowLogs(request.build());
            result.addAll(page.flowLogs());
            nextToken = page.nextToken();
        } while (nextToken != null && !nextToken.isBlank());
        return result;
    }

    private NetworkResource toFlowLogResource(FlowLog flowLog, String accountId, String region) {
        var config = objectMapper.createObjectNode();
        put(config, "flowLogId", flowLog.flowLogId());
        put(config, "resourceId", flowLog.resourceId());
        put(config, "trafficType", flowLog.trafficTypeAsString());
        put(config, "logDestination", flowLog.logDestination());
        put(config, "logGroupName", flowLog.logGroupName());
        put(config, "logDestinationType", flowLog.logDestinationTypeAsString());
        put(config, "flowLogStatus", flowLog.flowLogStatus() == null ? null : flowLog.flowLogStatus().toString());
        put(config, "deliverLogsStatus", flowLog.deliverLogsStatus());
        put(config, "logFormat", flowLog.logFormat());
        config.put("maxAggregationInterval", flowLog.maxAggregationInterval());
        List<NetworkRelationship> relationships = new ArrayList<>();
        String targetId = flowLog.resourceId();
        String targetType = resourceTypeForId(targetId);
        if (targetType != null) {
            relationships.add(new NetworkRelationship(targetType, targetId, null));
        }
        return new NetworkResource("AWS::EC2::FlowLog", flowLog.flowLogId(), flowLog.flowLogId(),
                accountId, region, config, List.copyOf(relationships));
    }

    private static String resourceTypeForId(String resourceId) {
        if (resourceId == null) return null;
        if (resourceId.startsWith("vpc-")) return "AWS::EC2::VPC";
        if (resourceId.startsWith("eni-")) return "AWS::EC2::NetworkInterface";
        if (resourceId.startsWith("subnet-")) return "AWS::EC2::Subnet";
        if (resourceId.startsWith("rtb-")) return "AWS::EC2::RouteTable";
        if (resourceId.startsWith("sg-")) return "AWS::EC2::SecurityGroup";
        if (resourceId.startsWith("acl-")) return "AWS::EC2::NetworkAcl";
        if (resourceId.startsWith("tgw-attach-")) return "AWS::EC2::TransitGatewayAttachment";
        if (resourceId.startsWith("tgw-rtb-")) return "AWS::EC2::TransitGatewayRouteTable";
        if (resourceId.startsWith("tgw-")) return "AWS::EC2::TransitGateway";
        if (resourceId.startsWith("pcx-")) return "AWS::EC2::VPCPeeringConnection";
        if (resourceId.startsWith("vpce-")) return "AWS::EC2::VPCEndpoint";
        if (resourceId.startsWith("i-")) return "AWS::EC2::Instance";
        return null;
    }

    private static void put(com.fasterxml.jackson.databind.node.ObjectNode object, String key, String value) {
        if (value != null) object.put(key, value);
    }

    private ResourceKey resourceKey(ResourceIdentifier identifier) {
        var builder = ResourceKey.builder().resourceType(identifier.resourceType()).resourceId(identifier.resourceId());
        return builder.build();
    }

    private NetworkResource toResource(
            software.amazon.awssdk.services.config.model.BaseConfigurationItem item,
            String fallbackAccountId, String fallbackRegion) {
        JsonNode configuration = null;
        try {
            if (item.configuration() != null && !item.configuration().isBlank()) {
                configuration = objectMapper.readTree(item.configuration());
            }
        } catch (Exception ignored) {
            // Keep this item and mark it as having no parseable config rather than failing the full snapshot.
        }
        List<NetworkRelationship> relationships = references(configuration);
        return new NetworkResource(item.resourceType().toString(), item.resourceId(), item.resourceName(),
                valueOr(item.accountId(), fallbackAccountId), valueOr(item.awsRegion(), fallbackRegion),
                configuration, relationships);
    }

    private static List<NetworkRelationship> references(JsonNode configuration) {
        if (configuration == null) return List.of();
        Map<String, NetworkRelationship> references = new LinkedHashMap<>();
        collectReferences(configuration, references);
        return List.copyOf(references.values());
    }

    private static void collectReferences(JsonNode node, Map<String, NetworkRelationship> references) {
        if (node == null) return;
        if (node.isObject()) {
            node.fields().forEachRemaining(entry -> {
                String targetType = REFERENCE_FIELDS.get(entry.getKey());
                if (targetType != null) {
                    addReferenceValues(entry.getValue(), targetType, references);
                } else if (entry.getKey().equals("gatewayId")) {
                    addGatewayReference(entry.getValue(), references);
                }
                collectReferences(entry.getValue(), references);
            });
        } else if (node.isArray()) {
            node.forEach(child -> collectReferences(child, references));
        }
    }

    private static void addReferenceValues(JsonNode value, String targetType,
                                           Map<String, NetworkRelationship> references) {
        if (value.isArray()) {
            value.forEach(item -> addReferenceValues(item, targetType, references));
        } else if (value.isTextual() && !value.asText().isBlank()) {
            String id = value.asText();
            references.putIfAbsent(targetType + ":" + id, new NetworkRelationship(targetType, id, null));
        }
    }

    private static void addGatewayReference(JsonNode value, Map<String, NetworkRelationship> references) {
        if (!value.isTextual()) return;
        String id = value.asText();
        String targetType = resourceTypeForId(id);
        if (targetType != null) {
            references.putIfAbsent(targetType + ":" + id, new NetworkRelationship(targetType, id, null));
        }
    }

    private static String valueOr(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private static String failureCode(SdkException failure) {
        if (failure instanceof AwsServiceException serviceFailure
                && serviceFailure.awsErrorDetails() != null
                && serviceFailure.awsErrorDetails().errorCode() != null) {
            return serviceFailure.awsErrorDetails().errorCode().replaceAll("[^A-Za-z0-9_.-]", "_");
        }
        return failure.getClass().getSimpleName().replaceAll("[^A-Za-z0-9_.-]", "_");
    }

    private static NetworkInventory unavailable(String warning) {
        return new NetworkInventory(Instant.now(), false, false, false, List.of(), NETWORK_RESOURCE_TYPES,
                Map.of(), List.of(), List.of(), List.of(), List.of("CONFIG_RECORDER_QUERY_FAILED_" + warning));
    }
}
