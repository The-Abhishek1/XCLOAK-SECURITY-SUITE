DROP INDEX IF EXISTS idx_alerts_agent_created_at;
DROP TABLE IF EXISTS correlation_rule_stages;
ALTER TABLE correlation_rules DROP COLUMN IF EXISTS threshold;
ALTER TABLE correlation_rules DROP COLUMN IF EXISTS window_minutes;
ALTER TABLE correlation_rules DROP COLUMN IF EXISTS correlation_type;
