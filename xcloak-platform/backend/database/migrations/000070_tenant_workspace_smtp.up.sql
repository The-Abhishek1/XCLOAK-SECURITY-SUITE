-- Add stable workspace_id UUID to tenants (never reused even after deletion)
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS workspace_id UUID NOT NULL DEFAULT gen_random_uuid();
CREATE UNIQUE INDEX IF NOT EXISTS tenants_workspace_id_key ON tenants (workspace_id);

-- Per-tenant SMTP configuration (overrides system .env SMTP for that tenant's emails)
CREATE TABLE IF NOT EXISTS tenant_smtp_configs (
    tenant_id   INT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    host        TEXT NOT NULL DEFAULT '',
    port        TEXT NOT NULL DEFAULT '587',
    username    TEXT NOT NULL DEFAULT '',
    password    TEXT NOT NULL DEFAULT '',
    from_addr   TEXT NOT NULL DEFAULT '',
    tls         BOOLEAN NOT NULL DEFAULT true,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
