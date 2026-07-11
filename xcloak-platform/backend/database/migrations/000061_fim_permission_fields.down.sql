ALTER TABLE fim_baselines
    DROP COLUMN IF EXISTS file_mode,
    DROP COLUMN IF EXISTS file_uid,
    DROP COLUMN IF EXISTS file_gid,
    DROP COLUMN IF EXISTS mod_time;

ALTER TABLE fim_alerts
    DROP COLUMN IF EXISTS old_mode,
    DROP COLUMN IF EXISTS new_mode,
    DROP COLUMN IF EXISTS old_uid,
    DROP COLUMN IF EXISTS new_uid;
