-- Grant xcloak_app DML access to ALL tables in the public schema.
-- Migration 000050 only granted the 6 RLS-protected tables; every other
-- table the API touches (users, tenants, agent_tasks, playbooks, etc.)
-- was still served by the privileged schema-owner role, which bypasses RLS.
-- This migration closes that gap so APP_DB_USER=xcloak_app is fully
-- operational and RLS is load-bearing end-to-end.

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES   IN SCHEMA public TO xcloak_app;
GRANT USAGE, SELECT                  ON ALL SEQUENCES IN SCHEMA public TO xcloak_app;

-- Ensure tables and sequences created by future migrations also inherit
-- these grants automatically (runs in the context of the schema owner).
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES    TO xcloak_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT                  ON SEQUENCES TO xcloak_app;
