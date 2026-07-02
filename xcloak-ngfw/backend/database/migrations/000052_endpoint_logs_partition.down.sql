-- Reverse partitioning: detach default partition, drop partitioned parent,
-- rename legacy heap table back to endpoint_logs.
BEGIN;

DROP FUNCTION IF EXISTS create_endpoint_logs_partition(DATE);

DO $$
DECLARE
    r RECORD;
BEGIN
    -- Detach all month partitions
    FOR r IN
        SELECT c.relname
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        WHERE i.inhparent = 'endpoint_logs'::regclass
          AND c.relname != 'endpoint_logs_legacy'
    LOOP
        EXECUTE format('ALTER TABLE endpoint_logs DETACH PARTITION %I', r.relname);
        EXECUTE format('DROP TABLE IF EXISTS %I', r.relname);
    END LOOP;

    -- Detach legacy
    IF EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'endpoint_logs'::regclass
          AND inhrelid  = 'endpoint_logs_legacy'::regclass
    ) THEN
        ALTER TABLE endpoint_logs DETACH PARTITION endpoint_logs_legacy;
    END IF;
END;
$$;

DROP TABLE IF EXISTS endpoint_logs;
ALTER TABLE IF EXISTS endpoint_logs_legacy RENAME TO endpoint_logs;

COMMIT;
