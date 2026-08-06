ALTER TABLE mdm_devices
    DROP COLUMN IF EXISTS manufacturer,
    DROP COLUMN IF EXISTS hardware,
    DROP COLUMN IF EXISTS security_patch_level,
    DROP COLUMN IF EXISTS android_sdk_version,
    DROP COLUMN IF EXISTS usb_debugging_enabled,
    DROP COLUMN IF EXISTS unknown_sources_enabled,
    DROP COLUMN IF EXISTS vpn_active,
    DROP COLUMN IF EXISTS battery_level,
    DROP COLUMN IF EXISTS battery_charging,
    DROP COLUMN IF EXISTS network_type,
    DROP COLUMN IF EXISTS wifi_ssid,
    DROP COLUMN IF EXISTS storage_total_gb,
    DROP COLUMN IF EXISTS storage_free_gb,
    DROP COLUMN IF EXISTS ram_total_mb,
    DROP COLUMN IF EXISTS build_fingerprint,
    DROP COLUMN IF EXISTS biometric_enrolled,
    DROP COLUMN IF EXISTS system_app_count,
    DROP COLUMN IF EXISTS high_risk_app_count;

ALTER TABLE mdm_device_apps
    DROP COLUMN IF EXISTS is_system_app,
    DROP COLUMN IF EXISTS dangerous_permissions;
