CREATE TABLE pathguard_hosted_github_source (
    source_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    repository VARCHAR(128) NOT NULL,
    workflow_name VARCHAR(128) NOT NULL,
    service_name VARCHAR(128) NOT NULL,
    environment_name VARCHAR(64) NOT NULL,
    connection_id VARCHAR(128) NOT NULL,
    created_by VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    next_poll_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_success_at TIMESTAMP WITH TIME ZONE,
    last_error_code VARCHAR(64),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    CONSTRAINT uq_hosted_github_tenant_source UNIQUE (
        tenant_id, repository, workflow_name, service_name, environment_name
    ),
    CONSTRAINT fk_hosted_github_connector FOREIGN KEY (tenant_id, source_id)
        REFERENCES pathguard_connectors (tenant_id, connector_id)
);

CREATE INDEX ix_hosted_github_due ON pathguard_hosted_github_source (enabled, next_poll_at);
CREATE INDEX ix_hosted_github_tenant ON pathguard_hosted_github_source (tenant_id, created_at DESC);
