CREATE TABLE pathguard_site_connector_heartbeats (
    connector_id UUID PRIMARY KEY REFERENCES pathguard_connectors(connector_id),
    overall_status VARCHAR(16) NOT NULL CHECK (overall_status IN ('OK', 'PARTIAL', 'FAILED')),
    checked_at TIMESTAMP WITH TIME ZONE NOT NULL,
    received_at TIMESTAMP WITH TIME ZONE NOT NULL,
    source_checks TEXT NOT NULL
);

CREATE INDEX idx_pathguard_site_heartbeat_received
    ON pathguard_site_connector_heartbeats(received_at DESC);
