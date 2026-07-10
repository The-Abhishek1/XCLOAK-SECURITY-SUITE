DROP INDEX IF EXISTS idx_endpoint_logs_tenant_collected;
ALTER TABLE endpoint_logs DROP COLUMN IF EXISTS tenant_id;
