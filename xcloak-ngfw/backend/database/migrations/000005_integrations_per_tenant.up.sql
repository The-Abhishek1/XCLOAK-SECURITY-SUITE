-- The 000004 migration gave integrations a tenant_id column, but left the
-- old UNIQUE(name) constraint in place — meaning there can only ever be one
-- 'webhook'/'slack'/'email' row platform-wide, so one tenant configuring
-- their Slack webhook silently overwrites it for every other tenant too.
-- Replace it with UNIQUE(name, tenant_id) so each tenant gets its own row.
ALTER TABLE integrations DROP CONSTRAINT integrations_name_key;
ALTER TABLE integrations ADD CONSTRAINT integrations_name_tenant_key UNIQUE (name, tenant_id);
