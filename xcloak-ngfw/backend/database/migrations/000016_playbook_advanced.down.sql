DROP TABLE IF EXISTS playbook_step_results;

ALTER TABLE playbook_executions
    DROP COLUMN IF EXISTS overall_status,
    DROP COLUMN IF EXISTS steps_total,
    DROP COLUMN IF EXISTS steps_ok,
    DROP COLUMN IF EXISTS steps_failed,
    DROP COLUMN IF EXISTS steps_skipped,
    DROP COLUMN IF EXISTS duration_ms;

ALTER TABLE playbook_actions
    DROP COLUMN IF EXISTS condition_expr,
    DROP COLUMN IF EXISTS max_retries,
    DROP COLUMN IF EXISTS retry_delay_secs,
    DROP COLUMN IF EXISTS run_parallel,
    DROP COLUMN IF EXISTS timeout_seconds;
