DROP TABLE IF EXISTS tenant_smtp_configs;
DROP INDEX IF EXISTS tenants_workspace_id_key;
ALTER TABLE tenants DROP COLUMN IF EXISTS workspace_id;
