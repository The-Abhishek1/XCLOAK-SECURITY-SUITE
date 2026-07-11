-- Persist platform-specific metrics that agents already send on every heartbeat
-- but were previously dropped (not in model or repository).
--
-- Desktop (Linux/Windows): load averages, logged-in users, open file descriptors.
-- Mobile (Android): battery, network, storage, security posture booleans.
--
-- All columns are nullable so older agent binaries that don't send these fields
-- keep working unchanged (missing fields stay NULL instead of defaulting to 0).

ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS load_avg_1m      REAL,
    ADD COLUMN IF NOT EXISTS load_avg_5m      REAL,
    ADD COLUMN IF NOT EXISTS load_avg_15m     REAL,
    ADD COLUMN IF NOT EXISTS logged_in_users  INT,
    ADD COLUMN IF NOT EXISTS open_fds         INT,
    ADD COLUMN IF NOT EXISTS battery_level    INT,
    ADD COLUMN IF NOT EXISTS battery_charging BOOLEAN,
    ADD COLUMN IF NOT EXISTS network_type     VARCHAR(30),
    ADD COLUMN IF NOT EXISTS is_rooted        BOOLEAN,
    ADD COLUMN IF NOT EXISTS developer_mode   BOOLEAN,
    ADD COLUMN IF NOT EXISTS storage_free_gb  REAL,
    ADD COLUMN IF NOT EXISTS storage_total_gb REAL,
    ADD COLUMN IF NOT EXISTS vpn_active       BOOLEAN,
    ADD COLUMN IF NOT EXISTS security_patch   VARCHAR(30);
