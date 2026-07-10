-- Row-Level Security (RLS) for tenant isolation.
--
-- Purpose: defense-in-depth layer on top of the application's existing
-- WHERE tenant_id = $N clauses. RLS makes it impossible for a DB query
-- to accidentally read another tenant's data even if the application
-- WHERE clause is omitted.
--
-- How it works at runtime:
--   1. The backend sets a per-transaction GUC before any tenant query:
--        SET LOCAL app.tenant_id = '<id>';
--      (SET LOCAL resets automatically when the transaction ends, which
--       makes it safe under PgBouncer transaction pooling.)
--   2. Each policy checks:
--        tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INTEGER
--      The second arg TRUE makes current_setting() return NULL instead of
--      raising an error when the GUC is not set (migration runs, superuser
--      maintenance, etc.), so RLS never blocks legitimate admin operations.
--
-- Roles:
--   The application must connect as xcloak_app (created below), NOT as the
--   DB owner / superuser. Superusers and table owners with BYPASSRLS bypass
--   all policies silently. xcloak_app has no BYPASSRLS privilege.
--
--   Migration scripts run as the DB owner (which bypasses RLS), so
--   migration itself is never blocked.
--
-- Tables covered: agents, alerts, incidents, endpoint_logs, sigma_rules, iocs
--   (the six highest-value tables for cross-tenant data leakage).

-- ── Application role ─────────────────────────────────────────────────────────
-- Create a limited-privilege role for the Go backend to use.
-- If it already exists (re-run), skip creation.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'xcloak_app') THEN
    CREATE ROLE xcloak_app LOGIN PASSWORD 'change_me_in_production';
  END IF;
END
$$;

-- Grant DML on tenant-scoped tables; deny DDL.
GRANT SELECT, INSERT, UPDATE, DELETE ON agents            TO xcloak_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON alerts             TO xcloak_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON incidents          TO xcloak_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON endpoint_logs      TO xcloak_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON sigma_rules        TO xcloak_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON iocs               TO xcloak_app;

-- Sequence access so INSERT ... RETURNING id works.
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO xcloak_app;

-- ── Enable RLS ───────────────────────────────────────────────────────────────
-- FORCE RLS applies policies even to the table owner (belt-and-suspenders).
ALTER TABLE agents       ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents       FORCE  ROW LEVEL SECURITY;

ALTER TABLE alerts        ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts        FORCE  ROW LEVEL SECURITY;

ALTER TABLE incidents     ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents     FORCE  ROW LEVEL SECURITY;

ALTER TABLE endpoint_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpoint_logs FORCE  ROW LEVEL SECURITY;

ALTER TABLE sigma_rules   ENABLE ROW LEVEL SECURITY;
ALTER TABLE sigma_rules   FORCE  ROW LEVEL SECURITY;

ALTER TABLE iocs          ENABLE ROW LEVEL SECURITY;
ALTER TABLE iocs          FORCE  ROW LEVEL SECURITY;

-- ── Tenant-isolation policies ────────────────────────────────────────────────
-- All four operations (SELECT/INSERT/UPDATE/DELETE) are scoped to the GUC.
-- current_setting(..., TRUE) returns NULL when unset → policy allows
-- the row only when tenant_id matches, so unset = no rows visible.
-- For INSERT, WITH CHECK prevents inserting rows for another tenant.

-- agents
CREATE POLICY tenant_isolation ON agents
  FOR ALL
  USING     (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INTEGER)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INTEGER);

-- alerts
CREATE POLICY tenant_isolation ON alerts
  FOR ALL
  USING     (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INTEGER)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INTEGER);

-- incidents
CREATE POLICY tenant_isolation ON incidents
  FOR ALL
  USING     (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INTEGER)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INTEGER);

-- endpoint_logs — tenant is derived from the parent agent
CREATE POLICY tenant_isolation ON endpoint_logs
  FOR ALL
  USING (
    agent_id IN (
      SELECT id FROM agents
      WHERE tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INTEGER
    )
  );

-- sigma_rules
CREATE POLICY tenant_isolation ON sigma_rules
  FOR ALL
  USING     (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INTEGER)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INTEGER);

-- iocs
CREATE POLICY tenant_isolation ON iocs
  FOR ALL
  USING     (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INTEGER)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', TRUE), '')::INTEGER);
