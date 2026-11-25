package io.pathguard.backend.security;

import java.util.UUID;

/** Tenant identity derived only from a validated human identity token. */
public record TenantIdentity(UUID tenantId, String subject) {
    public TenantIdentity {
        if (tenantId == null || subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("tenantId and subject are required");
        }
    }
}
