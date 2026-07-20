-- log_sources had no uniqueness constraint on (tenant_id, name), so the
-- `ON CONFLICT DO NOTHING` clauses in cmd/seed/demo and cmd/seed/rules were
-- silent no-ops — every re-run of a seed script duplicated all of its rows.
-- Dedupe existing rows (keep the lowest id per tenant_id+name) before adding
-- the constraint that makes ON CONFLICT DO NOTHING actually work going forward.

DELETE FROM log_sources a USING log_sources b
WHERE a.tenant_id = b.tenant_id
  AND a.name = b.name
  AND a.id > b.id;

CREATE UNIQUE INDEX IF NOT EXISTS log_sources_tenant_name_key ON log_sources (tenant_id, name);
