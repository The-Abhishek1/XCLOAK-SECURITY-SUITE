-- Per-tenant email domain → SSO mapping.
-- When a user enters their email on the login page, we extract the domain and
-- look it up here; if found, we redirect them straight into SSO for that
-- tenant without requiring them to know the org slug.
CREATE TABLE IF NOT EXISTS tenant_domains (
    id          SERIAL PRIMARY KEY,
    tenant_id   INT  NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain      TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(domain)
);
CREATE INDEX IF NOT EXISTS idx_td_tenant ON tenant_domains(tenant_id);
