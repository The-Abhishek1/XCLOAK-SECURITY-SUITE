-- Per-agent per-hour-of-week behavioral baselines (EMA of activity metrics).
-- hour_of_week = (weekday * 24 + hour), range 0-167.
CREATE TABLE IF NOT EXISTS agent_behavior_baselines (
    id              SERIAL      PRIMARY KEY,
    agent_id        INT         NOT NULL,
    tenant_id       INT         NOT NULL,
    hour_of_week    INT         NOT NULL CHECK (hour_of_week BETWEEN 0 AND 167),
    avg_log_count   FLOAT       NOT NULL DEFAULT 0,
    avg_login_fail  FLOAT       NOT NULL DEFAULT 0,
    avg_conn_count  FLOAT       NOT NULL DEFAULT 0,
    sample_count    INT         NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(agent_id, hour_of_week)
);

CREATE INDEX IF NOT EXISTS idx_abb_agent ON agent_behavior_baselines(agent_id);

-- Scored anomaly snapshots: one row per agent per 5-minute scoring cycle.
CREATE TABLE IF NOT EXISTS agent_anomaly_scores (
    id          SERIAL      PRIMARY KEY,
    agent_id    INT         NOT NULL,
    tenant_id   INT         NOT NULL,
    score       INT         NOT NULL CHECK (score BETWEEN 0 AND 100),
    components  JSONB       NOT NULL DEFAULT '{}',
    scored_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_aas_agent_time ON agent_anomaly_scores(agent_id, scored_at DESC);
CREATE INDEX IF NOT EXISTS idx_aas_tenant_time ON agent_anomaly_scores(tenant_id, scored_at DESC);

-- Add score + acknowledged to anomaly_findings.
ALTER TABLE anomaly_findings
    ADD COLUMN IF NOT EXISTS score        INT     NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS source       TEXT    NOT NULL DEFAULT 'ai'; -- ai | behavioral
