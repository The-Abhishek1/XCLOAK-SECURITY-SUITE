-- Rule groups and metadata.
ALTER TABLE firewall_rules
    ADD COLUMN IF NOT EXISTS group_name  TEXT   NOT NULL DEFAULT 'default',
    ADD COLUMN IF NOT EXISTS description TEXT   NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS hit_count   BIGINT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_fr_group_tenant ON firewall_rules(group_name, tenant_id);

-- Per-agent hit reports (agents submit counters every ~60s).
CREATE TABLE IF NOT EXISTS firewall_rule_hits (
    id          SERIAL      PRIMARY KEY,
    rule_id     INT         NOT NULL,
    agent_id    INT         NOT NULL,
    tenant_id   INT         NOT NULL,
    hits        BIGINT      NOT NULL DEFAULT 0,
    reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_frh_rule_tenant ON firewall_rule_hits(rule_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_frh_tenant_time ON firewall_rule_hits(tenant_id, reported_at DESC);
