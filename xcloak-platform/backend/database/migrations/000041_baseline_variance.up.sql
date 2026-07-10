-- Add EWMA variance columns + two new metrics to agent_behavior_baselines.
-- Existing rows get variance = 0 (no observations yet), which means the
-- baseline scorer will use the minimum-sigma floor until enough samples
-- accumulate — identical to the previous fixed-30%-of-mean behaviour.
ALTER TABLE agent_behavior_baselines
    ADD COLUMN IF NOT EXISTS var_log_count   DOUBLE PRECISION NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS var_login_fail  DOUBLE PRECISION NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS var_conn_count  DOUBLE PRECISION NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS avg_proc_count  DOUBLE PRECISION NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS var_proc_count  DOUBLE PRECISION NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS avg_priv_esc    DOUBLE PRECISION NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS var_priv_esc    DOUBLE PRECISION NOT NULL DEFAULT 0;

-- Process novelty catalog: tracks every distinct process name seen on each
-- agent. A new row (seen_count = 1) triggers a novelty finding.
CREATE TABLE IF NOT EXISTS agent_known_processes (
    agent_id     INTEGER      NOT NULL,
    process_name TEXT         NOT NULL,
    tenant_id    INTEGER      NOT NULL,
    first_seen   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    seen_count   INTEGER      NOT NULL DEFAULT 1,
    PRIMARY KEY (agent_id, process_name)
);
CREATE INDEX IF NOT EXISTS idx_akp_tenant ON agent_known_processes (tenant_id);
