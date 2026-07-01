DROP INDEX IF EXISTS idx_assets_platform;
DROP INDEX IF EXISTS idx_agents_platform;
ALTER TABLE assets DROP COLUMN IF EXISTS platform_category;
ALTER TABLE agents DROP COLUMN IF EXISTS platform_category;
