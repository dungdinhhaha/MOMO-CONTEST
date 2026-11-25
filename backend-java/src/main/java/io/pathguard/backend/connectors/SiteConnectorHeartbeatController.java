package io.pathguard.backend.connectors;

import com.fasterxml.jackson.databind.JsonNode;
import io.pathguard.backend.security.ConnectorIdentity;
import io.pathguard.backend.security.TenantIdentity;
import java.time.Instant;
import java.util.Iterator;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** Outbound-only on-prem connector status API. The backend never probes private site addresses. */
@RestController
@RequestMapping("/api/v1")
public class SiteConnectorHeartbeatController {
    private static final Set<String> HEARTBEAT_FIELDS = Set.of("checkedAt", "overallStatus", "sources");
    private static final Set<String> SOURCE_FIELDS = Set.of("name", "status", "checkedAt", "errorCode");
    private final SiteConnectorHeartbeatService service;

    public SiteConnectorHeartbeatController(SiteConnectorHeartbeatService service) {
        this.service = service;
    }

    @PostMapping("/site-connector/heartbeat")
    public SiteConnectorHeartbeatService.HeartbeatAccepted heartbeat(@RequestBody JsonNode body, Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof ConnectorIdentity connector)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Connector authentication is required");
        }
        if (!"ON_PREM".equals(connector.connectorType())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "This endpoint accepts ON_PREM connectors only");
        }
        rejectUnknown(body, HEARTBEAT_FIELDS, "heartbeat");
        Instant checkedAt = instant(body, "checkedAt");
        String overall = text(body, "overallStatus");
        JsonNode sources = body.get("sources");
        if (sources == null || !sources.isArray() || sources.isEmpty() || sources.size() > 100) {
            throw badRequest("sources must contain between 1 and 100 checks");
        }
        Set<String> names = new HashSet<>();
        for (JsonNode source : sources) {
            rejectUnknown(source, SOURCE_FIELDS, "source check");
            String name = text(source, "name");
            if (!names.add(name)) throw badRequest("source names must be unique");
            String sourceStatus = text(source, "status");
            if (!Set.of("OK", "UNAVAILABLE", "ERROR", "NOT_CONFIGURED", "NOT_SELECTED").contains(sourceStatus)) {
                throw badRequest("source status is invalid");
            }
            Instant sourceCheckedAt = instant(source, "checkedAt");
            if (sourceCheckedAt.isAfter(Instant.now().plusSeconds(300))
                    || sourceCheckedAt.isBefore(Instant.now().minusSeconds(86400))) {
                throw badRequest("source checkedAt must be within the last 24 hours");
            }
            if (source.has("errorCode") && (!source.get("errorCode").isTextual()
                    || source.get("errorCode").asText().length() > 64
                    || !source.get("errorCode").asText().matches("[A-Za-z0-9_.-]+"))) {
                throw badRequest("errorCode must be a short code without raw error text");
            }
        }
        if (!Set.of("OK", "PARTIAL", "FAILED").contains(overall)) {
            throw badRequest("overallStatus must be OK, PARTIAL, or FAILED");
        }
        SiteConnectorHeartbeatService.HeartbeatAccepted result = service.record(connector, checkedAt, overall, sources);
        return result;
    }

    @GetMapping("/connectors/{connectorId}/status")
    public SiteConnectorHeartbeatService.ConnectionStatus status(
            @PathVariable UUID connectorId, Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof TenantIdentity tenant)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Tenant authentication is required");
        }
        return service.status(tenant.tenantId(), connectorId);
    }

    private static void rejectUnknown(JsonNode node, Set<String> fields, String label) {
        if (node == null || !node.isObject()) throw badRequest(label + " must be a JSON object");
        Iterator<String> it = node.fieldNames();
        while (it.hasNext()) {
            String key = it.next();
            if (!fields.contains(key)) throw badRequest("Unsupported " + label + " field: " + key);
        }
    }

    private static String text(JsonNode node, String key) {
        JsonNode value = node.get(key);
        if (value == null || !value.isTextual() || value.asText().isBlank() || value.asText().length() > 64) {
            throw badRequest(key + " must be a non-empty string of at most 64 characters");
        }
        return value.asText();
    }

    private static Instant instant(JsonNode node, String key) {
        try {
            return Instant.parse(text(node, key));
        } catch (RuntimeException e) {
            throw badRequest(key + " must be an ISO-8601 UTC timestamp");
        }
    }

    private static ResponseStatusException badRequest(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
