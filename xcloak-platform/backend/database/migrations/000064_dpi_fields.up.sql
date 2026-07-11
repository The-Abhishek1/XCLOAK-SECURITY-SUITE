-- Deep Packet Inspection enrichment fields for network_connect_events.
-- These are populated by the agent's passive inspector and sent alongside
-- the existing connect event fields.

ALTER TABLE network_connect_events
    ADD COLUMN IF NOT EXISTS sni              TEXT        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS http_host        TEXT        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS http_method      VARCHAR(16) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS http_path        TEXT        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS http_user_agent  TEXT        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS tls_version      VARCHAR(16) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS tls_cipher       TEXT        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS dpi_proto        VARCHAR(32) NOT NULL DEFAULT '', -- detected app-layer proto
    ADD COLUMN IF NOT EXISTS entropy_score    SMALLINT    NOT NULL DEFAULT 0;  -- 0-100 payload entropy

-- Store all DPI-derived findings in a dedicated table so they can be queried
-- independently from alerts and anomalies.
CREATE TABLE IF NOT EXISTS dpi_findings (
    id              BIGSERIAL   PRIMARY KEY,
    agent_id        INTEGER     NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    tenant_id       INTEGER     NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_type    TEXT        NOT NULL,  -- 'dga' | 'tls_anomaly' | 'http_pattern' | 'proto_confusion' | 'high_entropy'
    severity        TEXT        NOT NULL DEFAULT 'medium',
    score           SMALLINT    NOT NULL DEFAULT 0,
    indicator       TEXT        NOT NULL DEFAULT '',  -- domain, IP:port, UA, cipher, etc.
    description     TEXT        NOT NULL DEFAULT '',
    mitre_technique VARCHAR(20) NOT NULL DEFAULT '',
    raw_context     JSONB       NOT NULL DEFAULT '{}',
    alert_fired     BOOLEAN     NOT NULL DEFAULT false,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dpi_agent_time  ON dpi_findings(agent_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_dpi_tenant_time ON dpi_findings(tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_dpi_type        ON dpi_findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_nce_sni         ON network_connect_events(sni) WHERE sni != '';
CREATE INDEX IF NOT EXISTS idx_nce_host        ON network_connect_events(http_host) WHERE http_host != '';
