package io.pathguard.backend.security;

import java.util.UUID;

/** Connector identity resolved by the backend from a stored credential hash. */
public record ConnectorIdentity(UUID tenantId, UUID connectorId, String connectorType,
                                String connectionId, String siteId, String zoneId) {
    public ConnectorIdentity {
        if (tenantId == null || connectorId == null || connectorType == null || connectorType.isBlank()) {
            throw new IllegalArgumentException("tenantId, connectorId, and connectorType are required");
        }
    }
}
