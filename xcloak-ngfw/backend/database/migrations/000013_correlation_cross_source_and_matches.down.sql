DROP TABLE IF EXISTS correlation_matches;
ALTER TABLE correlation_rule_stages DROP COLUMN IF EXISTS source_type;
ALTER TABLE correlation_rules DROP COLUMN IF EXISTS condition_value;
ALTER TABLE correlation_rules DROP COLUMN IF EXISTS source_type;
