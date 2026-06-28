-- Asset Management / CMDB

CREATE TABLE IF NOT EXISTS assets (
    id                  SERIAL PRIMARY KEY,
    tenant_id           INTEGER NOT NULL REFERENCES tenants(id),
    agent_id            INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    name                TEXT NOT NULL,
    hostname            TEXT,
    ip_address          TEXT,
    asset_type          VARCHAR(50)  NOT NULL DEFAULT 'server',
    owner               TEXT,
    business_unit       TEXT,
    criticality         VARCHAR(20)  NOT NULL DEFAULT 'medium',
    data_classification VARCHAR(30)  NOT NULL DEFAULT 'internal',
    environment         VARCHAR(20)  NOT NULL DEFAULT 'production',
    location            TEXT,
    tags                JSONB        NOT NULL DEFAULT '[]',
    notes               TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_agent ON assets(agent_id) WHERE agent_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(tenant_id, criticality);
