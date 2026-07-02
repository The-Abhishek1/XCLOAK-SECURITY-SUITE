-- Migration 054: Create the endpoint_logs partition maintenance function.
--
-- Migration 052 (heap→partitioned table conversion) failed because the
-- original endpoint_logs.id is INTEGER (int4) but the new partitioned parent
-- defined it as BIGSERIAL (int8) — a type mismatch PostgreSQL rejects at
-- ATTACH PARTITION time. The full conversion is retried in migration 055 with
-- the correct column types.
--
-- This migration only creates the helper function (idempotent, safe to re-run)
-- so operators can call it manually. The Go scheduler (EnsureNextMonthPartition)
-- already implements partition creation inline in Go and does not call this
-- function, so startup is not blocked even when endpoint_logs is still a heap.

CREATE OR REPLACE FUNCTION create_endpoint_logs_partition(target_month DATE)
RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
    month_start DATE := date_trunc('month', target_month)::DATE;
    month_end   DATE := (month_start + INTERVAL '1 month')::DATE;
    part_name   TEXT := 'endpoint_logs_' || to_char(month_start, 'YYYY_MM');
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = part_name AND n.nspname = 'public'
    ) THEN
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF endpoint_logs
             FOR VALUES FROM (%L) TO (%L)',
            part_name, month_start, month_end
        );
        RAISE NOTICE 'Created partition %', part_name;
    END IF;
END;
$$;
