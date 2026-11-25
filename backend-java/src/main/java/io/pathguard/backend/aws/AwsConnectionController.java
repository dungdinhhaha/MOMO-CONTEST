package io.pathguard.backend.aws;

import com.fasterxml.jackson.databind.JsonNode;
import io.pathguard.backend.security.TenantIdentity;
import java.util.Iterator;
import java.util.Set;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** Performs a read-only connectivity probe against a customer-provided AWS role. */
@RestController
@RequestMapping("/api/v1/aws/connections")
public class AwsConnectionController {
    private static final Set<String> ALLOWED_FIELDS = Set.of(
            "connectionId", "roleArn", "expectedAccountId", "region");
    private static final Set<String> PREPARE_FIELDS = Set.of("connectionId");

    private final AwsConnectionService service;
    private final AwsExternalIdService externalIds;
    private final AwsNetworkSnapshotService snapshots;

    public AwsConnectionController(AwsConnectionService service, AwsExternalIdService externalIds,
                                   AwsNetworkSnapshotService snapshots) {
        this.service = service;
        this.externalIds = externalIds;
        this.snapshots = snapshots;
    }

    @PostMapping("/prepare")
    public PreparedConnection prepare(
            @AuthenticationPrincipal TenantIdentity tenant,
            Authentication authentication,
            @RequestBody JsonNode body) {
        requireAdmin(tenant, authentication);
        rejectUnknownFields(body, PREPARE_FIELDS);
        String connectionId = requiredText(body, "connectionId");
        validateConnectionId(connectionId);
        return new PreparedConnection(connectionId, externalIds.derive(tenant.tenantId(), connectionId),
                "Use this value in the target role trust policy's sts:ExternalId condition.");
    }

    @PostMapping("/test")
    public AwsConnectionService.ConnectionTestResult test(
            @AuthenticationPrincipal TenantIdentity tenant,
            Authentication authentication,
            @RequestBody JsonNode body) {
        requireAdmin(tenant, authentication);
        rejectUnknownFields(body, ALLOWED_FIELDS);
        String connectionId = requiredText(body, "connectionId");
        validateConnectionId(connectionId);
        var request = new AwsConnectionService.ConnectionTestRequest(
                connectionId, requiredText(body, "roleArn"),
                requiredText(body, "expectedAccountId"), requiredText(body, "region"));
        return service.testConnection(tenant.tenantId(), request,
                externalIds.derive(tenant.tenantId(), connectionId));
    }

    @org.springframework.web.bind.annotation.GetMapping("/{connectionId}/inventory")
    public AwsNetworkSnapshotService.AwsNetworkSnapshot inventory(
            @AuthenticationPrincipal TenantIdentity tenant, @org.springframework.web.bind.annotation.PathVariable String connectionId) {
        if (tenant == null || tenant.tenantId() == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Verified tenant identity is required");
        }
        validateConnectionId(connectionId);
        return snapshots.getLatest(tenant.tenantId(), connectionId);
    }

    private static void requireAdmin(TenantIdentity tenant, Authentication authentication) {
        if (tenant == null || tenant.tenantId() == null || tenant.subject() == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Verified tenant identity is required");
        }
        boolean admin = authentication != null && authentication.getAuthorities().stream()
                .anyMatch(authority -> "ROLE_TENANT_ADMIN".equals(authority.getAuthority()));
        if (!admin) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Tenant administrator role is required");
        }
    }

    private static void rejectUnknownFields(JsonNode body, Set<String> allowed) {
        if (body == null || !body.isObject()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "JSON object is required");
        }
        Iterator<String> fields = body.fieldNames();
        while (fields.hasNext()) {
            String name = fields.next();
            if (!allowed.contains(name)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported request field: " + name);
            }
        }
    }

    private static void validateConnectionId(String connectionId) {
        if (connectionId.length() > 128 || !connectionId.matches("[A-Za-z0-9._:-]+")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "connectionId must use 1-128 letters, digits, dot, underscore, colon, or hyphen");
        }
    }

    private static String requiredText(JsonNode body, String field) {
        JsonNode value = body.get(field);
        if (value == null || !value.isTextual() || value.asText().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " is required");
        }
        return value.asText();
    }

    private static String optionalText(JsonNode body, String field) {
        JsonNode value = body.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        if (!value.isTextual() || value.asText().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " must be a non-empty string");
        }
        return value.asText();
    }

    public record PreparedConnection(String connectionId, String externalId, String instruction) { }
}
