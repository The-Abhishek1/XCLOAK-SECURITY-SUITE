-- sigma_rules had no uniqueness constraint on (tenant_id, title), so the
-- `ON CONFLICT DO NOTHING` clause in cmd/seed/demo's seedSigmaRules was a
-- silent no-op — every re-run of the seed script duplicated all of its rows.
-- Same disease fixed for log_sources in 000071, found here while
-- investigating why the rule tester's cache-invalidation regression guard
-- kept failing: it wasn't a cache bug, it was 64 duplicate copies of a
-- single rule (1299 total rows for 31 actually-distinct rules on the demo
-- tenant) — disabling one copy by id left the other 63 still enabled.
-- Dedupe (keep the lowest id per tenant_id+title) before adding the
-- constraint that makes ON CONFLICT DO NOTHING actually work going forward.

DELETE FROM sigma_rules a USING sigma_rules b
WHERE a.tenant_id = b.tenant_id
  AND a.title = b.title
  AND a.id > b.id;

CREATE UNIQUE INDEX IF NOT EXISTS sigma_rules_tenant_title_key ON sigma_rules (tenant_id, title);
