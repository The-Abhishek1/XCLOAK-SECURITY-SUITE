-- api/log_search_enterprise.go's GetScheduledSearches/CreateScheduledSearch/
-- DeleteScheduledSearch have always queried this table, but no migration
-- ever created it. CreateScheduledSearch already has a graceful fallback for
-- this ("persistence unavailable"), so every create silently 201'd without
-- saving anything and the Scheduled Searches list stayed permanently empty.

CREATE TABLE IF NOT EXISTS scheduled_log_searches (
    id          SERIAL PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    query       TEXT NOT NULL DEFAULT '',
    time_range  TEXT NOT NULL DEFAULT '24h',
    schedule    TEXT NOT NULL DEFAULT 'daily',
    action      TEXT NOT NULL DEFAULT 'alert',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_run_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS scheduled_log_searches_tenant_idx ON scheduled_log_searches (tenant_id);
