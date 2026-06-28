CREATE TABLE IF NOT EXISTS risk_posture_snapshots (
    id          SERIAL PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    score       INTEGER NOT NULL,  -- 0-100, higher = worse
    vuln_score  INTEGER NOT NULL DEFAULT 0,
    ueba_score  INTEGER NOT NULL DEFAULT 0,
    alert_score INTEGER NOT NULL DEFAULT 0,
    ioc_score   INTEGER NOT NULL DEFAULT 0,
    asset_scores JSONB NOT NULL DEFAULT '[]', -- per-asset breakdown
    snapshot_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS hunt_templates (
    id          SERIAL PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    mitre_tactic    VARCHAR(100) NOT NULL DEFAULT '',
    mitre_technique VARCHAR(50)  NOT NULL DEFAULT '',
    kql_query   TEXT NOT NULL,
    schedule    VARCHAR(100) NOT NULL DEFAULT '', -- cron or empty
    is_active   BOOLEAN NOT NULL DEFAULT true,
    created_by  VARCHAR(100) NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS hunt_runs (
    id              SERIAL PRIMARY KEY,
    template_id     INTEGER REFERENCES hunt_templates(id) ON DELETE SET NULL,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    kql_query       TEXT NOT NULL,
    status          VARCHAR(30) NOT NULL DEFAULT 'running', -- running, completed, failed
    hit_count       INTEGER NOT NULL DEFAULT 0,
    findings        JSONB NOT NULL DEFAULT '[]',
    analyst         VARCHAR(100) NOT NULL DEFAULT '',
    severity        VARCHAR(20) NOT NULL DEFAULT 'medium',
    notes           TEXT NOT NULL DEFAULT '',
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_risk_posture_tenant ON risk_posture_snapshots(tenant_id, snapshot_at DESC);
CREATE INDEX IF NOT EXISTS idx_hunt_templates_tenant ON hunt_templates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_hunt_runs_tenant ON hunt_runs(tenant_id, started_at DESC);
