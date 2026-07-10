DROP TABLE IF EXISTS sigma_rule_hits;

ALTER TABLE sigma_rules
    DROP COLUMN IF EXISTS description,
    DROP COLUMN IF EXISTS logsource_cat,
    DROP COLUMN IF EXISTS logsource_prod,
    DROP COLUMN IF EXISTS logsource_svc,
    DROP COLUMN IF EXISTS status,
    DROP COLUMN IF EXISTS tags,
    DROP COLUMN IF EXISTS falsepositives,
    DROP COLUMN IF EXISTS references;
