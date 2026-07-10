-- Drop policies first, then disable RLS.
DROP POLICY IF EXISTS tenant_isolation ON agents;
DROP POLICY IF EXISTS tenant_isolation ON alerts;
DROP POLICY IF EXISTS tenant_isolation ON incidents;
DROP POLICY IF EXISTS tenant_isolation ON endpoint_logs;
DROP POLICY IF EXISTS tenant_isolation ON sigma_rules;
DROP POLICY IF EXISTS tenant_isolation ON iocs;

ALTER TABLE agents       DISABLE ROW LEVEL SECURITY;
ALTER TABLE alerts        DISABLE ROW LEVEL SECURITY;
ALTER TABLE incidents     DISABLE ROW LEVEL SECURITY;
ALTER TABLE endpoint_logs DISABLE ROW LEVEL SECURITY;
ALTER TABLE sigma_rules   DISABLE ROW LEVEL SECURITY;
ALTER TABLE iocs          DISABLE ROW LEVEL SECURITY;

-- Note: role xcloak_app is NOT dropped here — it may hold other privileges.
-- Drop manually if needed: DROP ROLE xcloak_app;
