CREATE TABLE IF NOT EXISTS user_risk_profiles (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    username VARCHAR(255) NOT NULL,
    source VARCHAR(20) NOT NULL DEFAULT 'endpoint',
    risk_score INTEGER NOT NULL DEFAULT 0,
    total_events INTEGER NOT NULL DEFAULT 0,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    off_hours_events INTEGER NOT NULL DEFAULT 0,
    unique_ips INTEGER NOT NULL DEFAULT 0,
    privilege_escalations INTEGER NOT NULL DEFAULT 0,
    flags TEXT[] NOT NULL DEFAULT '{}',
    last_seen_ip TEXT,
    last_event_at TIMESTAMPTZ,
    analyzed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, username, source)
);
CREATE INDEX IF NOT EXISTS idx_urp_tenant ON user_risk_profiles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_urp_score ON user_risk_profiles(tenant_id, risk_score DESC);

CREATE TABLE IF NOT EXISTS ueba_events (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    username VARCHAR(255) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'low',
    description TEXT NOT NULL,
    source_ip TEXT,
    agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    raw_log TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ueba_tenant ON ueba_events(tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_ueba_user ON ueba_events(tenant_id, username, detected_at DESC);

CREATE TABLE IF NOT EXISTS feed_sync_log (
    id SERIAL PRIMARY KEY,
    feed_id INTEGER NOT NULL REFERENCES threat_feeds(id) ON DELETE CASCADE,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id),
    status VARCHAR(20) NOT NULL,
    iocs_added INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_fsl_feed ON feed_sync_log(feed_id, synced_at DESC);
