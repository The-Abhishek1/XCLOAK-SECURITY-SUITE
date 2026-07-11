-- Extend FIM tables to store file permission and ownership metadata.
-- The agent already collects mode/uid/gid but the backend was silently
-- dropping them, creating a blind spot for setuid additions, ownership
-- hijacks, and chmod-based persistence that don't change the file hash.

ALTER TABLE fim_baselines
    ADD COLUMN IF NOT EXISTS file_mode VARCHAR(12) DEFAULT '',
    ADD COLUMN IF NOT EXISTS file_uid  INT         DEFAULT 0,
    ADD COLUMN IF NOT EXISTS file_gid  INT         DEFAULT 0,
    ADD COLUMN IF NOT EXISTS mod_time  TIMESTAMPTZ;

ALTER TABLE fim_alerts
    ADD COLUMN IF NOT EXISTS old_mode VARCHAR(12) DEFAULT '',
    ADD COLUMN IF NOT EXISTS new_mode VARCHAR(12) DEFAULT '',
    ADD COLUMN IF NOT EXISTS old_uid  INT         DEFAULT 0,
    ADD COLUMN IF NOT EXISTS new_uid  INT         DEFAULT 0;
