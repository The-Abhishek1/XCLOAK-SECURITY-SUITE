-- Add tenant_id to endpoint_logs for direct tenant isolation without JOIN.
-- This is required by P3.1 partitioning (partition key must be a column in
-- the table itself) and fixes the UEBA query bug where l.tenant_id=$1 was
-- referencing a non-existent column.

ALTER TABLE endpoint_logs ADD COLUMN IF NOT EXISTS tenant_id INTEGER;

-- Back-fill from agents table for all existing rows.
UPDATE endpoint_logs el
SET tenant_id = a.tenant_id
FROM agents a
WHERE a.id = el.agent_id
  AND el.tenant_id IS NULL;

-- Index for per-tenant range queries (used by UEBA, log search, retention).
CREATE INDEX IF NOT EXISTS idx_endpoint_logs_tenant_collected
    ON endpoint_logs (tenant_id, collected_at DESC);

-- Update the SaveLogs insert in the application to populate tenant_id
-- going forward (done in code; this migration only handles existing data).
