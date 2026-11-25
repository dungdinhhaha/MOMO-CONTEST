package io.pathguard.backend.connectors;

import java.util.Iterator;
import java.util.Set;
import java.util.UUID;

import com.fasterxml.jackson.databind.JsonNode;
import io.pathguard.backend.security.TenantIdentity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1")
public class ConnectorRegistryController {
    private static final Set<String> ENROLLMENT_FIELDS = Set.of(
            "connectorType", "connectionId", "siteId", "zoneId", "expiresInSeconds");
    private static final Set<String> EXCHANGE_FIELDS = Set.of("enrollmentToken");

    private final ConnectorRegistryService registry;

    public ConnectorRegistryController(ConnectorRegistryService registry) {
        this.registry = registry;
    }

    @PostMapping("/connectors/enrollments")
    public ResponseEntity<ConnectorRegistryService.EnrollmentIssued> createEnrollment(
            @AuthenticationPrincipal TenantIdentity tenant, Authentication authentication,
            @RequestBody JsonNode body) {
        requireTenant(tenant);
        requireTenantAdmin(authentication);
        rejectUnknownFields(body, ENROLLMENT_FIELDS);
        String connectorType = text(body, "connectorType", true);
        String connectionId = text(body, "connectionId", false);
        String siteId = text(body, "siteId", false);
        String zoneId = text(body, "zoneId", false);
        Integer ttl = integer(body, "expiresInSeconds");
        var issued = registry.createEnrollment(tenant.tenantId(), tenant.subject(), connectorType,
                connectionId, siteId, zoneId, ttl);
        return ResponseEntity.status(HttpStatus.CREATED).body(issued);
    }

    @PostMapping("/connectors/enroll")
    public ResponseEntity<ConnectorRegistryService.ConnectorIssued> exchangeEnrollment(
            @RequestBody JsonNode body) {
        rejectUnknownFields(body, EXCHANGE_FIELDS);
        String token = text(body, "enrollmentToken", true);
        return ResponseEntity.status(HttpStatus.CREATED).body(registry.exchangeEnrollment(token));
    }

    @GetMapping("/connectors")
    public ConnectorList list(@AuthenticationPrincipal TenantIdentity tenant) {
        requireTenant(tenant);
        return new ConnectorList(registry.listForTenant(tenant.tenantId()));
    }

    @DeleteMapping("/connectors/{connectorId}")
    public ResponseEntity<Void> revoke(@AuthenticationPrincipal TenantIdentity tenant,
                                       Authentication authentication, @PathVariable UUID connectorId) {
        requireTenant(tenant);
        requireTenantAdmin(authentication);
        registry.revoke(tenant.tenantId(), connectorId);
        return ResponseEntity.noContent().build();
    }

    private static void requireTenant(TenantIdentity tenant) {
        if (tenant == null || tenant.tenantId() == null || tenant.subject() == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Verified tenant identity is required");
        }
    }

    private static void requireTenantAdmin(Authentication authentication) {
        boolean isAdmin = authentication != null && authentication.getAuthorities().stream()
                .anyMatch(authority -> "ROLE_TENANT_ADMIN".equals(authority.getAuthority()));
        if (!isAdmin) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Tenant administrator role is required");
        }
    }

    private static void rejectUnknownFields(JsonNode body, Set<String> allowed) {
        if (body == null || !body.isObject()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "JSON object is required");
        }
        Iterator<String> names = body.fieldNames();
        while (names.hasNext()) {
            String field = names.next();
            if (!allowed.contains(field)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported request field: " + field);
            }
        }
    }

    private static String text(JsonNode body, String field, boolean required) {
        JsonNode value = body.get(field);
        if (value == null || value.isNull()) {
            if (required) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " is required");
            }
            return null;
        }
        if (!value.isTextual() || (required && value.asText().isBlank())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " must be a non-empty string");
        }
        return value.asText();
    }

    private static Integer integer(JsonNode body, String field) {
        JsonNode value = body.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        if (!value.canConvertToInt()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " must be an integer");
        }
        return value.intValue();
    }

    public record ConnectorList(java.util.List<ConnectorRegistryService.ConnectorView> connectors) { }
}
