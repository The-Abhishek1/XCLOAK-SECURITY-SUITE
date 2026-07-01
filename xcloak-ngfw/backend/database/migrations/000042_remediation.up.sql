-- Remediation plans tie a set of cleanup steps to an incident.
-- Each step maps to one agent task; the plan aggregates their statuses.

CREATE TABLE IF NOT EXISTS remediation_plans (
    id           SERIAL       PRIMARY KEY,
    incident_id  INTEGER      REFERENCES incidents(id) ON DELETE SET NULL,
    tenant_id    INTEGER      NOT NULL,
    agent_id     INTEGER      NOT NULL,
    label        TEXT         NOT NULL DEFAULT '',
    created_by   TEXT         NOT NULL,
    status       TEXT         NOT NULL DEFAULT 'pending'   -- pending | running | completed | partial | failed
                              CHECK (status IN ('pending','running','completed','partial','failed')),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_rp_tenant_incident ON remediation_plans (tenant_id, incident_id);

CREATE TABLE IF NOT EXISTS remediation_steps (
    id           SERIAL       PRIMARY KEY,
    plan_id      INTEGER      NOT NULL REFERENCES remediation_plans(id) ON DELETE CASCADE,
    step_order   INTEGER      NOT NULL DEFAULT 0,
    action_type  TEXT         NOT NULL,
    payload      JSONB        NOT NULL DEFAULT '{}',
    status       TEXT         NOT NULL DEFAULT 'pending'   -- pending | dispatched | completed | failed | skipped
                              CHECK (status IN ('pending','dispatched','completed','failed','skipped')),
    task_id      INTEGER,     -- FK to agent_tasks.id once dispatched
    result       TEXT         NOT NULL DEFAULT '',
    executed_at  TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_rs_plan ON remediation_steps (plan_id, step_order);

-- Memory dump artifacts are stored alongside regular forensic_artifacts.
-- The data column holds: { "size_bytes": N, "sha256": "...", "storage_path": "..." }
-- For the agent-side upload we reuse the existing /api/agents/file endpoint
-- with artifact_type = "memory_dump".
