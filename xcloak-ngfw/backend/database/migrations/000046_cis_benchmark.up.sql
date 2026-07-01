-- CIS Benchmark compliance scanning results.
-- One row per (agent, control_id); upserted on each scan run so the table
-- always reflects the most recent observed state.

CREATE TABLE IF NOT EXISTS cis_findings (
    id              SERIAL       PRIMARY KEY,
    tenant_id       INTEGER      NOT NULL,
    agent_id        INTEGER      NOT NULL,
    control_id      TEXT         NOT NULL,   -- e.g. CIS-L-2.2.1, CIS-W-1.1.4
    platform        TEXT         NOT NULL,   -- linux | windows
    profile         TEXT         NOT NULL DEFAULT 'Level 1',
    category        TEXT         NOT NULL,
    title           TEXT         NOT NULL,
    status          TEXT         NOT NULL,   -- pass | fail | warn | unknown
    severity        TEXT         NOT NULL,   -- info | low | medium | high | critical
    description     TEXT         NOT NULL,
    evidence        TEXT         NOT NULL DEFAULT '',
    remediation     TEXT         NOT NULL DEFAULT '',
    checked_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cis_agent_control
    ON cis_findings (agent_id, control_id);

CREATE INDEX IF NOT EXISTS idx_cis_tenant_status
    ON cis_findings (tenant_id, status, severity);

CREATE INDEX IF NOT EXISTS idx_cis_agent
    ON cis_findings (agent_id, checked_at DESC);
