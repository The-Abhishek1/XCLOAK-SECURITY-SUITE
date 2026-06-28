CREATE TABLE IF NOT EXISTS canary_tokens (
    id          SERIAL PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_type  VARCHAR(30) NOT NULL, -- file, api_key, url, dns
    name        VARCHAR(255) NOT NULL,
    token_value VARCHAR(512) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    deployed_to VARCHAR(255) NOT NULL DEFAULT '', -- hostname or path
    created_by  VARCHAR(100) NOT NULL DEFAULT '',
    alert_on_trip BOOLEAN NOT NULL DEFAULT true,
    is_active   BOOLEAN NOT NULL DEFAULT true,
    trip_count  INTEGER NOT NULL DEFAULT 0,
    last_tripped_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS canary_trips (
    id          SERIAL PRIMARY KEY,
    token_id    INTEGER NOT NULL REFERENCES canary_tokens(id) ON DELETE CASCADE,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source_ip   VARCHAR(64) NOT NULL DEFAULT '',
    user_agent  VARCHAR(512) NOT NULL DEFAULT '',
    method      VARCHAR(20) NOT NULL DEFAULT '',
    extra_data  JSONB NOT NULL DEFAULT '{}',
    tripped_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS honeyports (
    id          SERIAL PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id    INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    VARCHAR(10) NOT NULL DEFAULT 'tcp',
    description TEXT NOT NULL DEFAULT '',
    alert_severity VARCHAR(20) NOT NULL DEFAULT 'high',
    is_active   BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (agent_id, port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_canary_tokens_tenant ON canary_tokens(tenant_id);
CREATE INDEX IF NOT EXISTS idx_canary_trips_token   ON canary_trips(token_id);
CREATE INDEX IF NOT EXISTS idx_canary_trips_tenant  ON canary_trips(tenant_id, tripped_at DESC);
CREATE INDEX IF NOT EXISTS idx_honeyports_tenant    ON honeyports(tenant_id);
