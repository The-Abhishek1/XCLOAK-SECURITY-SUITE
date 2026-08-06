-- The mobile agent has sent a rich posture snapshot on every enrollment and
-- check-in since it was built (manufacturer, hardware, SDK version, battery,
-- network, storage, RAM, security-patch level, USB debugging / unknown
-- sources flags, build fingerprint) but mdm_devices had no columns for any
-- of it and the handlers silently dropped every one of these fields.
--
-- Also adds the per-app risk columns (is_system_app, dangerous_permissions)
-- the mobile app already collects and sends on /api/mdm/devices/:id/apps,
-- plus device-level system/high-risk app counts posted alongside the app
-- list and on the threat-scan endpoint, both previously dropped too.

ALTER TABLE mdm_devices
    ADD COLUMN IF NOT EXISTS manufacturer            TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS hardware                 TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS security_patch_level     VARCHAR(30) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS android_sdk_version      INTEGER,
    ADD COLUMN IF NOT EXISTS usb_debugging_enabled    BOOLEAN,
    ADD COLUMN IF NOT EXISTS unknown_sources_enabled  BOOLEAN,
    ADD COLUMN IF NOT EXISTS vpn_active               BOOLEAN,
    ADD COLUMN IF NOT EXISTS battery_level            INTEGER,
    ADD COLUMN IF NOT EXISTS battery_charging         BOOLEAN,
    ADD COLUMN IF NOT EXISTS network_type             VARCHAR(30) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS wifi_ssid                TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS storage_total_gb          REAL,
    ADD COLUMN IF NOT EXISTS storage_free_gb           REAL,
    ADD COLUMN IF NOT EXISTS ram_total_mb              INTEGER,
    ADD COLUMN IF NOT EXISTS build_fingerprint         TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS biometric_enrolled        BOOLEAN,
    ADD COLUMN IF NOT EXISTS system_app_count          INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS high_risk_app_count       INTEGER NOT NULL DEFAULT 0;

ALTER TABLE mdm_device_apps
    ADD COLUMN IF NOT EXISTS is_system_app          BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS dangerous_permissions   TEXT[] NOT NULL DEFAULT '{}';
