-- Tracks the mobile agent's periodic on-device threat scan (sideloaded app
-- count) — previously posted to POST /api/mdm/devices/:id/threat-scan, a
-- route that never existed on the backend, so every scan failed silently.
ALTER TABLE mdm_devices
    ADD COLUMN IF NOT EXISTS last_threat_scan_at  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS total_app_count       INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS sideloaded_app_count  INTEGER NOT NULL DEFAULT 0;
