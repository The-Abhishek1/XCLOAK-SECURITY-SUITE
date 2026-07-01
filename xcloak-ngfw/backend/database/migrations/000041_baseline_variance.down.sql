DROP TABLE IF EXISTS agent_known_processes;

ALTER TABLE agent_behavior_baselines
    DROP COLUMN IF EXISTS var_log_count,
    DROP COLUMN IF EXISTS var_login_fail,
    DROP COLUMN IF EXISTS var_conn_count,
    DROP COLUMN IF EXISTS avg_proc_count,
    DROP COLUMN IF EXISTS var_proc_count,
    DROP COLUMN IF EXISTS avg_priv_esc,
    DROP COLUMN IF EXISTS var_priv_esc;
