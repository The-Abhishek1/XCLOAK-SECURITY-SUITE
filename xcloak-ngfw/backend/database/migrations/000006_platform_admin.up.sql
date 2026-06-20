-- Platform-wide admin flag, independent of the per-tenant admin/analyst/viewer
-- role. No API ever sets this — it's promoted via direct SQL only, so there's
-- no self-escalation path. Used to gate tenant provisioning (creating new
-- tenants is a platform-operator action, not something any tenant's own
-- admin can do).
ALTER TABLE users ADD COLUMN is_platform_admin BOOLEAN NOT NULL DEFAULT false;
