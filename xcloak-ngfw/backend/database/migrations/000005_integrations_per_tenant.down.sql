-- If multiple tenants each configured their own row for the same
-- integration name (exactly what the up migration enables), re-adding a
-- global UNIQUE(name) constraint would fail outright on the duplicate-key
-- check. Collapse down to one row per name first (keep the lowest tenant_id,
-- i.e. the Default tenant's row where it exists) so the rollback can't abort
-- partway through with the old constraint dropped and the new one missing.
DELETE FROM integrations a
USING integrations b
WHERE a.name = b.name
  AND a.tenant_id > b.tenant_id;

ALTER TABLE integrations DROP CONSTRAINT integrations_name_tenant_key;
ALTER TABLE integrations ADD CONSTRAINT integrations_name_key UNIQUE (name);
