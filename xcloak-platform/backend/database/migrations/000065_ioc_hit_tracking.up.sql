-- IOC hit tracking: record when each indicator last fired and how many times.
-- Enables auto-expiry of stale IOCs that never produce matches.

ALTER TABLE iocs
  ADD COLUMN IF NOT EXISTS hit_count   INT          NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_seen   TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS expires_at  TIMESTAMPTZ;

-- Fast lookup for the expiry scheduler (runs nightly across all tenants).
CREATE INDEX IF NOT EXISTS idx_iocs_expiry
  ON iocs (tenant_id, enabled, expires_at, hit_count, created_at);
