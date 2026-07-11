ALTER TABLE endpoint_connections
    DROP COLUMN IF EXISTS pid,
    DROP COLUMN IF EXISTS process_name,
    DROP COLUMN IF EXISTS process_path;
