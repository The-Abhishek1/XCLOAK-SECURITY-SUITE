-- Saved log searches (named, reusable queries).
CREATE TABLE IF NOT EXISTS saved_log_searches (
    id          SERIAL      PRIMARY KEY,
    name        TEXT        NOT NULL,
    query       TEXT        NOT NULL DEFAULT '',
    filters     JSONB       NOT NULL DEFAULT '{}',
    time_range  TEXT        NOT NULL DEFAULT '24h',
    created_by  TEXT        NOT NULL DEFAULT '',
    tenant_id   INT         NOT NULL,
    run_count   INT         NOT NULL DEFAULT 0,
    last_run_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sls_tenant ON saved_log_searches(tenant_id);

-- Per-tenant log retention policy (one row per tenant, upserted on change).
CREATE TABLE IF NOT EXISTS log_retention_policies (
    tenant_id      INT         PRIMARY KEY,
    retention_days INT         NOT NULL DEFAULT 90,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
