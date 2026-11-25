package io.pathguard.backend.aws;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.pathguard.backend.aws.AwsReadOnlyProbe.AuditEvent;
import io.pathguard.backend.aws.AwsReadOnlyProbe.FlowTraffic;
import io.pathguard.backend.aws.AwsReadOnlyProbe.NetworkInventory;
import io.pathguard.backend.aws.AwsReadOnlyProbe.NetworkRelationship;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.GZIPInputStream;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.cloudtrail.CloudTrailClient;
import software.amazon.awssdk.services.cloudtrail.model.LookupAttribute;
import software.amazon.awssdk.services.cloudtrail.model.LookupEventsRequest;
import software.amazon.awssdk.services.cloudtrail.model.Resource;
import software.amazon.awssdk.services.cloudwatchlogs.CloudWatchLogsClient;
import software.amazon.awssdk.services.cloudwatchlogs.model.DescribeLogStreamsRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.GetLogEventsRequest;
import software.amazon.awssdk.services.cloudwatchlogs.model.OrderBy;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;

/** Collects bounded, read-only operational evidence from existing CloudTrail and Flow Log destinations. */
@Component
public class AwsOperationalEvidenceCollector {
    private static final List<String> AUDIT_EVENT_SOURCES = List.of(
            "ec2.amazonaws.com", "elasticloadbalancing.amazonaws.com", "ecs.amazonaws.com",
            "eks.amazonaws.com", "iam.amazonaws.com", "config.amazonaws.com",
            "cloudformation.amazonaws.com", "codedeploy.amazonaws.com", "codepipeline.amazonaws.com",
            "codebuild.amazonaws.com");
    private static final int MAX_AUDIT_EVENTS_PER_SOURCE = 200;
    private static final int MAX_AUDIT_PAGES_PER_SOURCE = 20;
    private static final int MAX_S3_OBJECTS = 50;
    private static final int MAX_FLOW_RECORDS = 20_000;
    private static final Duration FLOW_WINDOW = Duration.ofDays(7);
    private static final Duration AUDIT_WINDOW = Duration.ofDays(90);
    private static final DateTimeFormatter TWO_DIGITS = DateTimeFormatter.ofPattern("MM");
    private static final Logger LOG = LoggerFactory.getLogger(AwsOperationalEvidenceCollector.class);

    private final ObjectMapper mapper;

    public AwsOperationalEvidenceCollector(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public NetworkInventory collect(CloudTrailClient cloudTrail, CloudWatchLogsClient logs, S3Client s3,
                                    NetworkInventory inventory, String accountId, String region) {
        List<String> warnings = new ArrayList<>(inventory.warnings());
        long auditStarted = System.nanoTime();
        List<AuditEvent> auditEvents = collectAuditEvents(cloudTrail, warnings);
        LOG.info("AWS evidence CloudTrail collection finished: events={}, elapsedMs={}", auditEvents.size(),
                Duration.ofNanos(System.nanoTime() - auditStarted).toMillis());
        List<FlowTraffic> flowTraffic = new ArrayList<>();
        Instant now = Instant.now();
        Instant start = now.minus(FLOW_WINDOW);
        long flowStarted = System.nanoTime();
        for (var resource : inventory.resources()) {
            if (!"AWS::EC2::FlowLog".equals(resource.resourceType()) || resource.configuration() == null) {
                continue;
            }
            JsonNode config = resource.configuration();
            String destinationType = config.path("logDestinationType").asText("");
            String logFormat = config.path("logFormat").asText("");
            if (destinationType.equalsIgnoreCase("cloud-watch-logs")) {
                String group = config.path("logGroupName").asText("");
                if (!group.isBlank()) {
                    int before = flowTraffic.size();
                    long started = System.nanoTime();
                    collectCloudWatchLogs(logs, group, logFormat, start, now, flowTraffic, warnings);
                    LOG.info("AWS evidence CloudWatch Flow Logs finished: records={}, elapsedMs={}",
                            flowTraffic.size() - before, Duration.ofNanos(System.nanoTime() - started).toMillis());
                } else {
                    warnings.add("FLOW_LOG_GROUP_NAME_MISSING_" + safeId(resource.resourceId()));
                }
            } else if (destinationType.equalsIgnoreCase("s3")) {
                String destination = config.path("logDestination").asText("");
                int before = flowTraffic.size();
                long started = System.nanoTime();
                collectS3FlowLogs(s3, destination, accountId, region, logFormat, start, now,
                        flowTraffic, warnings);
                LOG.info("AWS evidence S3 Flow Logs finished: records={}, elapsedMs={}",
                        flowTraffic.size() - before, Duration.ofNanos(System.nanoTime() - started).toMillis());
            }
            if (flowTraffic.size() >= MAX_FLOW_RECORDS) break;
        }
        LOG.info("AWS evidence Flow Logs collection finished: records={}, elapsedMs={}", flowTraffic.size(),
                Duration.ofNanos(System.nanoTime() - flowStarted).toMillis());
        return new NetworkInventory(inventory.collectedAt(), inventory.apiReachable(), inventory.recorderFound(),
                inventory.recording(), inventory.recordedResourceTypes(), inventory.uncoveredResourceTypes(),
                inventory.resourceCounts(), inventory.resources(), List.copyOf(auditEvents),
                List.copyOf(flowTraffic), List.copyOf(warnings));
    }

    private List<AuditEvent> collectAuditEvents(CloudTrailClient client, List<String> warnings) {
        List<AuditEvent> result = new ArrayList<>();
        Instant startTime = Instant.now().minus(AUDIT_WINDOW);
        for (String eventSource : AUDIT_EVENT_SOURCES) {
            String nextToken = null;
            int collectedForSource = 0;
            int pagesRead = 0;
            try {
                do {
                    var builder = LookupEventsRequest.builder()
                            .startTime(startTime)
                            .maxResults(50)
                            .lookupAttributes(LookupAttribute.builder()
                                    .attributeKey("EventSource").attributeValue(eventSource).build());
                    if (nextToken != null) builder.nextToken(nextToken);
                    var page = client.lookupEvents(builder.build());
                    pagesRead++;
                    for (var event : page.events()) {
                        if (collectedForSource >= MAX_AUDIT_EVENTS_PER_SOURCE) break;
                        AuditEvent normalized = normalizeAuditEvent(event);
                        if (normalized != null) {
                            result.add(normalized);
                            collectedForSource++;
                        }
                    }
                    nextToken = page.nextToken();
                } while (nextToken != null && collectedForSource < MAX_AUDIT_EVENTS_PER_SOURCE
                        && pagesRead < MAX_AUDIT_PAGES_PER_SOURCE);
                if (nextToken != null && pagesRead >= MAX_AUDIT_PAGES_PER_SOURCE) {
                    warnings.add("CLOUDTRAIL_PAGE_LIMIT_REACHED_" + safeSource(eventSource));
                }
            } catch (SdkException failure) {
                warnings.add("CLOUDTRAIL_LOOKUP_FAILED_" + safeSource(eventSource) + "_" + failureCode(failure));
            }
        }
        return result;
    }

    private AuditEvent normalizeAuditEvent(software.amazon.awssdk.services.cloudtrail.model.Event event) {
        JsonNode detail;
        try {
            detail = event.cloudTrailEvent() == null ? mapper.createObjectNode()
                    : mapper.readTree(event.cloudTrailEvent());
        } catch (Exception ignored) {
            return null;
        }
        if (detail.path("readOnly").asBoolean(false)) return null;
        List<NetworkRelationship> resources = new ArrayList<>();
        for (Resource resource : event.resources()) {
            String type = normalizeResourceType(resource.resourceType());
            if (type != null && resource.resourceName() != null) {
                resources.add(new NetworkRelationship(type, resource.resourceName(), null));
            }
        }
        return new AuditEvent(event.eventId(), event.eventTime(), event.eventSource(), event.eventName(),
                event.username(), List.copyOf(resources));
    }

    private String normalizeResourceType(String type) {
        if (type == null) return null;
        if (type.startsWith("AWS::")) return type;
        Map<String, String> types = Map.ofEntries(
                Map.entry("AWS::EC2::VPC", "AWS::EC2::VPC"),
                Map.entry("AWS::EC2::Subnet", "AWS::EC2::Subnet"),
                Map.entry("AWS::EC2::Instance", "AWS::EC2::Instance"),
                Map.entry("AWS::EC2::NetworkInterface", "AWS::EC2::NetworkInterface"),
                Map.entry("AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroup"),
                Map.entry("AWS::EC2::RouteTable", "AWS::EC2::RouteTable"),
                Map.entry("AWS::EC2::VPCPeeringConnection", "AWS::EC2::VPCPeeringConnection"));
        return types.get(type);
    }

    private void collectCloudWatchLogs(CloudWatchLogsClient client, String logGroup, String logFormat,
                                       Instant start, Instant end, List<FlowTraffic> output,
                                       List<String> warnings) {
        try {
            var streams = client.describeLogStreams(DescribeLogStreamsRequest.builder()
                    .logGroupName(logGroup).orderBy(OrderBy.LAST_EVENT_TIME).descending(true).limit(20).build());
            AtomicInteger totalRecords = new AtomicInteger(output.size());
            ConcurrentLinkedQueue<FlowTraffic> parsed = new ConcurrentLinkedQueue<>();
            ConcurrentLinkedQueue<String> streamWarnings = new ConcurrentLinkedQueue<>();
            List<software.amazon.awssdk.services.cloudwatchlogs.model.LogStream> selected = streams.logStreams()
                    .stream().filter(stream -> stream.logStreamName() != null).toList();
            ExecutorService executor = Executors.newFixedThreadPool(Math.min(5, Math.max(1, selected.size())));
            try {
                List<CompletableFuture<Void>> reads = selected.stream().map(stream -> CompletableFuture.runAsync(() -> {
                    String token = null;
                    try {
                        do {
                            var request = GetLogEventsRequest.builder().logGroupName(logGroup)
                                    .logStreamName(stream.logStreamName()).startTime(start.toEpochMilli())
                                    .endTime(end.toEpochMilli()).startFromHead(false).limit(10_000);
                            if (token != null) request.nextToken(token);
                            var page = client.getLogEvents(request.build());
                            for (var event : page.events()) {
                                int slot = totalRecords.getAndIncrement();
                                if (slot >= MAX_FLOW_RECORDS) return;
                                FlowTraffic traffic = parseFlowRecord(event.message(), logFormat,
                                        "cloudwatch:" + logGroup, event.timestamp());
                                if (traffic != null) parsed.add(traffic);
                                else totalRecords.decrementAndGet();
                            }
                            String next = page.nextForwardToken();
                            if (next == null || next.equals(token)) break;
                            token = next;
                        } while (true);
                    } catch (SdkException failure) {
                        streamWarnings.add("CLOUDWATCH_FLOW_LOG_STREAM_READ_FAILED_" + failureCode(failure));
                    }
                }, executor)).toList();
                CompletableFuture.allOf(reads.toArray(CompletableFuture[]::new)).join();
            } finally {
                executor.shutdown();
            }
            output.addAll(parsed);
            warnings.addAll(streamWarnings);
        } catch (SdkException failure) {
            warnings.add("CLOUDWATCH_FLOW_LOG_READ_FAILED_" + failureCode(failure));
        }
    }

    private void collectS3FlowLogs(S3Client client, String destination, String accountId, String region,
                                   String logFormat, Instant start, Instant end, List<FlowTraffic> output,
                                   List<String> warnings) {
        BucketPrefix bucketPrefix = parseS3Destination(destination);
        if (bucketPrefix == null) {
            warnings.add("S3_FLOW_LOG_DESTINATION_UNSUPPORTED");
            return;
        }
        try {
            List<software.amazon.awssdk.services.s3.model.S3Object> candidates = new ArrayList<>();
            for (LocalDate date = LocalDate.ofInstant(start, ZoneOffset.UTC);
                 !date.isAfter(LocalDate.ofInstant(end, ZoneOffset.UTC)); date = date.plusDays(1)) {
                String prefix = join(bucketPrefix.prefix(), "AWSLogs/" + accountId + "/vpcflowlogs/" + region + "/"
                        + date.getYear() + "/" + date.format(TWO_DIGITS) + "/" + date.format(DateTimeFormatter.ofPattern("dd")) + "/");
                String token = null;
                do {
                    var request = ListObjectsV2Request.builder().bucket(bucketPrefix.bucket())
                            .prefix(prefix).maxKeys(1000);
                    if (token != null) request.continuationToken(token);
                    var page = client.listObjectsV2(request.build());
                    for (var object : page.contents()) {
                        if (object.key() != null && object.key().endsWith(".gz")
                                && object.size() != null && object.size() > 0) candidates.add(object);
                    }
                    token = page.nextContinuationToken();
                } while (token != null);
            }
            List<software.amazon.awssdk.services.s3.model.S3Object> selected = candidates.stream()
                    .sorted(Comparator.comparing(software.amazon.awssdk.services.s3.model.S3Object::key).reversed())
                    .limit(MAX_S3_OBJECTS).toList();
            AtomicInteger totalRecords = new AtomicInteger(output.size());
            ConcurrentLinkedQueue<FlowTraffic> parsed = new ConcurrentLinkedQueue<>();
            ConcurrentLinkedQueue<String> objectWarnings = new ConcurrentLinkedQueue<>();
            ExecutorService executor = Executors.newFixedThreadPool(Math.min(5, Math.max(1, selected.size())));
            try {
                List<CompletableFuture<Void>> reads = selected.stream().map(object -> CompletableFuture.runAsync(() -> {
                    try (var response = client.getObject(GetObjectRequest.builder()
                                 .bucket(bucketPrefix.bucket()).key(object.key()).build());
                         var gzip = new GZIPInputStream(response);
                         var reader = new BufferedReader(new InputStreamReader(gzip,
                                 java.nio.charset.StandardCharsets.UTF_8))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            int slot = totalRecords.getAndIncrement();
                            if (slot >= MAX_FLOW_RECORDS) break;
                            FlowTraffic traffic = parseFlowRecord(line, logFormat, "s3:" + object.key(), null);
                            if (traffic != null) parsed.add(traffic);
                            else totalRecords.decrementAndGet();
                        }
                    } catch (SdkException | java.io.IOException failure) {
                        objectWarnings.add("S3_FLOW_LOG_OBJECT_READ_FAILED_" + failureCode(failure));
                    }
                }, executor)).toList();
                CompletableFuture.allOf(reads.toArray(CompletableFuture[]::new)).join();
            } finally {
                executor.shutdown();
            }
            output.addAll(parsed);
            warnings.addAll(objectWarnings);
        } catch (SdkException failure) {
            warnings.add("S3_FLOW_LOG_READ_FAILED_" + failureCode(failure));
        }
    }

    private FlowTraffic parseFlowRecord(String message, String format, String destination, Long eventMillis) {
        if (message == null || message.isBlank() || message.startsWith("version ")) return null;
        String[] values = message.trim().split("\\s+");
        String[] keys = format == null || format.isBlank() ? defaultFlowKeys()
                : format.trim().split("\\s+");
        if (values.length != keys.length) return null;
        Map<String, String> fields = new HashMap<>();
        for (int index = 0; index < keys.length; index++) {
            String key = keys[index].replace("${", "").replace("}", "");
            fields.put(key, values[index]);
        }
        Instant start = epoch(fields.get("start"));
        Instant finish = epoch(fields.get("end"));
        if (start == null && eventMillis != null) start = Instant.ofEpochMilli(eventMillis);
        return new FlowTraffic(start, finish, nullable(fields.get("interface-id")),
                nullable(fields.get("srcaddr")), nullable(fields.get("dstaddr")),
                integer(fields.get("srcport")), integer(fields.get("dstport")), nullable(fields.get("protocol")),
                longValue(fields.get("packets")), longValue(fields.get("bytes")),
                nullable(fields.get("action")), nullable(fields.get("log-status")), destination);
    }

    private static String[] defaultFlowKeys() {
        return new String[]{"${version}", "${account-id}", "${interface-id}", "${srcaddr}", "${dstaddr}",
                "${srcport}", "${dstport}", "${protocol}", "${packets}", "${bytes}", "${start}",
                "${end}", "${action}", "${log-status}"};
    }

    private static BucketPrefix parseS3Destination(String raw) {
        if (raw == null) return null;
        String value = raw.startsWith("arn:aws:s3:::") ? raw.substring("arn:aws:s3:::".length())
                : raw.startsWith("s3://") ? raw.substring("s3://".length()) : null;
        if (value == null) return null;
        int separator = value.indexOf('/');
        String bucket = separator < 0 ? value : value.substring(0, separator);
        String prefix = separator < 0 ? "" : value.substring(separator + 1);
        return bucket.isBlank() ? null : new BucketPrefix(bucket, prefix);
    }

    private static String join(String prefix, String suffix) {
        if (prefix == null || prefix.isBlank()) return suffix;
        return prefix.replaceAll("/+$", "") + "/" + suffix;
    }

    private static Instant epoch(String value) {
        try { return value == null || value.equals("-") ? null : Instant.ofEpochSecond(Long.parseLong(value)); }
        catch (RuntimeException ignored) { return null; }
    }

    private static Integer integer(String value) {
        try { return value == null || value.equals("-") ? null : Integer.valueOf(value); }
        catch (RuntimeException ignored) { return null; }
    }

    private static Long longValue(String value) {
        try { return value == null || value.equals("-") ? null : Long.valueOf(value); }
        catch (RuntimeException ignored) { return null; }
    }

    private static String nullable(String value) { return value == null || value.equals("-") ? null : value; }

    private static String safeId(String value) {
        return value == null ? "UNKNOWN" : value.replaceAll("[^A-Za-z0-9_-]", "_");
    }

    private static String safeSource(String value) { return value.replaceAll("[^A-Za-z0-9_-]", "_"); }

    private static String failureCode(Throwable failure) {
        if (failure instanceof AwsServiceException serviceFailure
                && serviceFailure.awsErrorDetails() != null && serviceFailure.awsErrorDetails().errorCode() != null) {
            return serviceFailure.awsErrorDetails().errorCode().replaceAll("[^A-Za-z0-9_.-]", "_");
        }
        return failure.getClass().getSimpleName().replaceAll("[^A-Za-z0-9_.-]", "_");
    }

    private record BucketPrefix(String bucket, String prefix) { }
}
