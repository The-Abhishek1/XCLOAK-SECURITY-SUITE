DROP TABLE IF EXISTS firewall_rule_hits;
ALTER TABLE firewall_rules
    DROP COLUMN IF EXISTS hit_count,
    DROP COLUMN IF EXISTS description,
    DROP COLUMN IF EXISTS group_name;
