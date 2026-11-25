CREATE TABLE pathguard_aws_network_snapshot (
    snapshot_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    connection_id VARCHAR(128) NOT NULL,
    account_id CHAR(12) NOT NULL,
    region VARCHAR(32) NOT NULL,
    collected_at TIMESTAMP WITH TIME ZONE NOT NULL,
    coverage_status VARCHAR(16) NOT NULL,
    resource_count INTEGER NOT NULL,
    resource_counts JSON NOT NULL,
    missing_resource_types JSON NOT NULL,
    warnings JSON NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    payload_json JSON NOT NULL
);

CREATE INDEX ix_aws_snapshot_tenant_connection_collected
    ON pathguard_aws_network_snapshot (tenant_id, connection_id, collected_at DESC, snapshot_id);
