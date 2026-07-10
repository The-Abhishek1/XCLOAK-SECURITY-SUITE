-- Alert investigation context cache
CREATE TABLE IF NOT EXISTS alert_investigation_cache (
    alert_id INTEGER PRIMARY KEY REFERENCES alerts(id) ON DELETE CASCADE,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id),
    ioc_hits JSONB NOT NULL DEFAULT '[]',
    similar_alerts JSONB NOT NULL DEFAULT '[]',
    mitre_context JSONB NOT NULL DEFAULT '{}',
    suggested_cases JSONB NOT NULL DEFAULT '[]',
    enriched_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_aic_tenant ON alert_investigation_cache(tenant_id);
