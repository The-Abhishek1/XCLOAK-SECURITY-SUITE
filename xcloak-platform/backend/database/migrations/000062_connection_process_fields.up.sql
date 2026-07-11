-- Extend endpoint_connections with the process that owns each socket.
-- The desktop agent already collects PID, process name, and exe path from
-- /proc, but the backend was silently dropping them, making it impossible
-- to answer "which process opened this suspicious connection?"

ALTER TABLE endpoint_connections
    ADD COLUMN IF NOT EXISTS pid          INT          DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS process_name VARCHAR(255) DEFAULT '',
    ADD COLUMN IF NOT EXISTS process_path TEXT         DEFAULT '';
