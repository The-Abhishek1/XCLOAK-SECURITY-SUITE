CREATE TABLE IF NOT EXISTS forensic_collections (
    id          SERIAL PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    agent_id    INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    label       VARCHAR(255) NOT NULL DEFAULT 'Forensic Collection',
    status      VARCHAR(30)  NOT NULL DEFAULT 'pending', -- pending, running, completed, failed
    artifact_types TEXT[]    NOT NULL DEFAULT '{}',
    triggered_by VARCHAR(255),
    started_at  TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS forensic_artifacts (
    id              SERIAL PRIMARY KEY,
    collection_id   INTEGER NOT NULL REFERENCES forensic_collections(id) ON DELETE CASCADE,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id        INTEGER REFERENCES agents(id),
    artifact_type   VARCHAR(100) NOT NULL, -- processes, connections, file_hashes, services, users, auth_logs
    data            JSONB NOT NULL DEFAULT '[]',
    item_count      INTEGER NOT NULL DEFAULT 0,
    collected_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_forensic_collections_tenant ON forensic_collections(tenant_id);
CREATE INDEX IF NOT EXISTS idx_forensic_collections_incident ON forensic_collections(incident_id);
CREATE INDEX IF NOT EXISTS idx_forensic_artifacts_collection ON forensic_artifacts(collection_id);
