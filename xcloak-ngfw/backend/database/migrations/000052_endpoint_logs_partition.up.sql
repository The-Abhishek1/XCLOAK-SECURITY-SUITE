-- Convert endpoint_logs to a declaratively partitioned table (RANGE on collected_at).
--
-- Strategy: rename the existing heap table to a "legacy" partition that covers
-- all historical data, then create the new partitioned parent as endpoint_logs.
-- Future log inserts go to monthly child partitions; retention purges drop
-- entire month partitions instead of running DELETE loops.
--
-- Constraints:
--   1. The primary key on the new parent must include the partition key.
--   2. Foreign keys FROM other tables pointing at endpoint_logs.id are not
--      supported on partitioned tables (Postgres 14 limitation). We DROP
--      those FKs here; the application enforces referential integrity via
--      agent_id + collected_at range.
--   3. This migration is idempotent: it checks for the partitioned parent
--      before re-creating it.

BEGIN;

-- ── Step 1: Drop FK constraints that reference endpoint_logs.id ──────────────
-- (Postgres does not allow FKs to partitioned tables as of PG 16)
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT conname, conrelid::regclass AS tbl
        FROM pg_constraint
        WHERE confrelid = 'endpoint_logs'::regclass
          AND contype = 'f'
    LOOP
        EXECUTE format('ALTER TABLE %s DROP CONSTRAINT IF EXISTS %I', r.tbl, r.conname);
    END LOOP;
END;
$$;

-- ── Step 2: Rename existing table to a "legacy" name ─────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'endpoint_logs_legacy'
          AND n.nspname = 'public'
    ) THEN
        ALTER TABLE endpoint_logs RENAME TO endpoint_logs_legacy;
    END IF;
END;
$$;

-- ── Step 3: Create the new partitioned parent ─────────────────────────────────
-- Use SERIAL (int4) to match the original table's id INTEGER column type.
CREATE TABLE IF NOT EXISTS endpoint_logs (
    id          SERIAL,
    agent_id    INTEGER,
    tenant_id   BIGINT NOT NULL DEFAULT 1,
    log_source  VARCHAR(100),
    log_message TEXT,
    collected_at TIMESTAMP WITHOUT TIME ZONE DEFAULT now(),
    parsed_fields JSONB DEFAULT '{}'::jsonb,
    PRIMARY KEY (id, collected_at)         -- PK must include partition key
) PARTITION BY RANGE (collected_at);

-- ── Step 4: Add (id, collected_at) unique constraint needed for ATTACH ────────
-- The partitioned parent's PRIMARY KEY (id, collected_at) requires each child
-- to have a matching unique constraint. The legacy table only has PK (id).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'endpoint_logs_legacy'::regclass
          AND conname  = 'endpoint_logs_legacy_id_collected_at_key'
    ) AND EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'endpoint_logs_legacy' AND n.nspname = 'public'
    ) THEN
        ALTER TABLE endpoint_logs_legacy
            ADD CONSTRAINT endpoint_logs_legacy_id_collected_at_key
            UNIQUE (id, collected_at);
    END IF;
END;
$$;

-- ── Step 5: Attach legacy data as the default partition ───────────────────────
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'endpoint_logs'::regclass
          AND inhrelid  = 'endpoint_logs_legacy'::regclass
    ) THEN
        ALTER TABLE endpoint_logs ATTACH PARTITION endpoint_logs_legacy DEFAULT;
    END IF;
END;
$$;

-- ── Step 6: Pre-create the current and next 3 months of partitions ────────────
DO $$
DECLARE
    month_start DATE;
    month_end   DATE;
    part_name   TEXT;
BEGIN
    FOR i IN 0..3 LOOP
        month_start := date_trunc('month', CURRENT_DATE + (i || ' months')::INTERVAL)::DATE;
        month_end   := (month_start + INTERVAL '1 month')::DATE;
        part_name   := 'endpoint_logs_' || to_char(month_start, 'YYYY_MM');

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
        END IF;
    END LOOP;
END;
$$;

-- ── Step 6: Indexes on the partitioned parent (inherited by all partitions) ───
CREATE INDEX IF NOT EXISTS idx_el_tenant_collected
    ON endpoint_logs (tenant_id, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_el_agent_collected
    ON endpoint_logs (agent_id, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_el_parsed_fields_gin
    ON endpoint_logs USING GIN (parsed_fields);

-- ── Step 7: Auto-partition maintenance function ───────────────────────────────
-- Called by the Go retention scheduler each month to create the next
-- partition before it's needed. Also called by a pg_cron job if available.
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

-- ── Step 8: Drop old partition function (if retention scheduler created one) ──
-- The retention loop in log_search_service.go can now DROP a whole partition
-- instead of batched-DELETE:
-- DROP TABLE IF EXISTS endpoint_logs_YYYY_MM;

COMMIT;
