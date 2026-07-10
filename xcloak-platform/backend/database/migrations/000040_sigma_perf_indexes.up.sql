-- Partial index on sigma_rules for the hot cache-miss path:
--   GetEnabledRules(tenantID) → WHERE enabled = true AND tenant_id = $1
-- Without this, every 30-second cache refresh (per active tenant) does a
-- sequential scan.  The partial index (WHERE enabled = true) is smaller
-- than a full two-column index and matches the query exactly.
CREATE INDEX IF NOT EXISTS idx_sigma_rules_tenant_enabled
    ON sigma_rules (tenant_id)
    WHERE enabled = true;

-- endpoint_logs lookups for the live-log stream use agent_id + id (cursor).
-- Without this the SELECT … WHERE agent_id=$1 AND id>$2 scans all logs.
CREATE INDEX IF NOT EXISTS idx_endpoint_logs_agent_id
    ON endpoint_logs (agent_id, id);
