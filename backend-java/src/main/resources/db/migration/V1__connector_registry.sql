CREATE TABLE pathguard_connector_enrollments (
    enrollment_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    connector_id UUID NOT NULL UNIQUE,
    connector_type VARCHAR(32) NOT NULL CHECK (connector_type IN ('AWS', 'ON_PREM')),
    connection_id VARCHAR(128),
    site_id VARCHAR(128),
    zone_id VARCHAR(128),
    enrollment_token_hash CHAR(64) NOT NULL UNIQUE,
    created_by VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_pathguard_enrollment_tenant ON pathguard_connector_enrollments(tenant_id, created_at);

CREATE TABLE pathguard_connectors (
    connector_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    connector_type VARCHAR(32) NOT NULL CHECK (connector_type IN ('AWS', 'ON_PREM')),
    connection_id VARCHAR(128),
    site_id VARCHAR(128),
    zone_id VARCHAR(128),
    credential_hash CHAR(64) NOT NULL UNIQUE,
    created_by VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen_at TIMESTAMP WITH TIME ZONE,
    revoked_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_pathguard_connector_tenant ON pathguard_connectors(tenant_id, created_at);
