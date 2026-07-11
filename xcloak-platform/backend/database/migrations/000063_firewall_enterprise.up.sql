-- Enterprise firewall enhancements

ALTER TABLE firewall_rules
    ADD COLUMN IF NOT EXISTS direction   TEXT        NOT NULL DEFAULT 'both',   -- in | out | both
    ADD COLUMN IF NOT EXISTS port_range  TEXT        NOT NULL DEFAULT '',        -- "8000-9000" or "80,443,8080"
    ADD COLUMN IF NOT EXISTS log_enabled BOOLEAN     NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS log_prefix  TEXT        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS expires_at  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS tags        TEXT[]      NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS created_by  TEXT        NOT NULL DEFAULT 'system',
    ADD COLUMN IF NOT EXISTS updated_by  TEXT        NOT NULL DEFAULT 'system',
    ADD COLUMN IF NOT EXISTS updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Auto-disable expired rules hourly (function + cron handled by app scheduler).
CREATE INDEX IF NOT EXISTS idx_fr_expires ON firewall_rules(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_fr_tags    ON firewall_rules USING GIN(tags);

-- Per-tenant firewall policy (default-deny vs default-allow).
CREATE TABLE IF NOT EXISTS firewall_policy (
    tenant_id      INTEGER     PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    default_action TEXT        NOT NULL DEFAULT 'allow',  -- 'allow' | 'deny'
    updated_by     TEXT        NOT NULL DEFAULT 'system',
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
