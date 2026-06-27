-- Rule metadata fields
ALTER TABLE sigma_rules
    ADD COLUMN IF NOT EXISTS description    TEXT     NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS logsource_cat  TEXT     NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS logsource_prod TEXT     NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS logsource_svc  TEXT     NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS status         TEXT     NOT NULL DEFAULT 'experimental',
    ADD COLUMN IF NOT EXISTS tags           JSONB    NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS falsepositives JSONB    NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS references     JSONB    NOT NULL DEFAULT '[]';

-- Track every rule match for analytics (hit counts, last-fired, top agents)
CREATE TABLE IF NOT EXISTS sigma_rule_hits (
    id         SERIAL      PRIMARY KEY,
    rule_id    INT         NOT NULL,
    agent_id   INT         NOT NULL,
    tenant_id  INT         NOT NULL,
    matched_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_srh_rule_tenant ON sigma_rule_hits(rule_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_srh_tenant_time ON sigma_rule_hits(tenant_id, matched_at DESC);
