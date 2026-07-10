-- Advanced step-level controls on each action
ALTER TABLE playbook_actions
    ADD COLUMN IF NOT EXISTS condition_expr   TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS max_retries      INT     NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS retry_delay_secs INT     NOT NULL DEFAULT 5,
    ADD COLUMN IF NOT EXISTS run_parallel     BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS timeout_seconds  INT     NOT NULL DEFAULT 30;

-- Execution-level summary (one row per playbook run, not per action)
ALTER TABLE playbook_executions
    ADD COLUMN IF NOT EXISTS overall_status TEXT NOT NULL DEFAULT 'completed',
    ADD COLUMN IF NOT EXISTS steps_total    INT  NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS steps_ok       INT  NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS steps_failed   INT  NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS steps_skipped  INT  NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS duration_ms    INT  NOT NULL DEFAULT 0;

-- Per-step execution results (drill-down from an execution)
CREATE TABLE IF NOT EXISTS playbook_step_results (
    id             SERIAL      PRIMARY KEY,
    execution_id   INT         NOT NULL,
    step_order     INT         NOT NULL,
    action_type    TEXT        NOT NULL,
    condition_expr TEXT        NOT NULL DEFAULT '',
    status         TEXT        NOT NULL,
    output         TEXT        NOT NULL DEFAULT '',
    error_detail   TEXT        NOT NULL DEFAULT '',
    retries_used   INT         NOT NULL DEFAULT 0,
    started_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_psr_execution ON playbook_step_results(execution_id);
