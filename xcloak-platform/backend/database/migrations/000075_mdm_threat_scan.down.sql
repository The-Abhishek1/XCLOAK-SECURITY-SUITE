ALTER TABLE mdm_devices
    DROP COLUMN IF EXISTS last_threat_scan_at,
    DROP COLUMN IF EXISTS total_app_count,
    DROP COLUMN IF EXISTS sideloaded_app_count;
