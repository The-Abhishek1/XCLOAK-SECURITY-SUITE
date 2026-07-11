DROP TABLE IF EXISTS firewall_policy;
ALTER TABLE firewall_rules
    DROP COLUMN IF EXISTS direction,
    DROP COLUMN IF EXISTS port_range,
    DROP COLUMN IF EXISTS log_enabled,
    DROP COLUMN IF EXISTS log_prefix,
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS tags,
    DROP COLUMN IF EXISTS created_by,
    DROP COLUMN IF EXISTS updated_by,
    DROP COLUMN IF EXISTS updated_at;
