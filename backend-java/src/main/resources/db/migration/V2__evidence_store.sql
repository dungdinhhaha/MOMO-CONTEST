ALTER TABLE pathguard_connectors
    ADD CONSTRAINT uq_pathguard_connector_tenant_pair UNIQUE (tenant_id, connector_id);

CREATE TABLE pathguard_evidence_bundle (
    bundle_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    connector_id UUID NOT NULL,
    connector_type VARCHAR(32) NOT NULL CHECK (connector_type IN ('AWS', 'ON_PREM')),
    connection_id VARCHAR(128),
    site_id VARCHAR(128),
    zone_id VARCHAR(128),
    schema_version VARCHAR(96) NOT NULL,
    collected_at TIMESTAMP WITH TIME ZONE NOT NULL,
    received_at TIMESTAMP WITH TIME ZONE NOT NULL,
    coverage_status VARCHAR(24) NOT NULL,
    record_count INTEGER NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    payload_json TEXT NOT NULL,
    CONSTRAINT uq_evidence_bundle_replay UNIQUE (tenant_id, connector_id, payload_sha256),
    CONSTRAINT fk_evidence_bundle_connector_tenant
        FOREIGN KEY (tenant_id, connector_id)
        REFERENCES pathguard_connectors (tenant_id, connector_id)
);

CREATE INDEX ix_evidence_tenant_received
    ON pathguard_evidence_bundle (tenant_id, received_at DESC, bundle_id);

CREATE INDEX ix_evidence_tenant_connector_received
    ON pathguard_evidence_bundle (tenant_id, connector_id, received_at DESC);
