-- Migration 054: Ensure the endpoint_logs partitioning from migration 052 is
-- fully applied. Migration 052 runs in a transaction; if the server was
-- restarted mid-run, its schema changes were rolled back but the dirty flag
-- was already set. The Migrate() auto-recovery now forces to version-1 and
-- re-runs, but as a belt-and-suspenders measure this migration re-creates
-- every artefact from 052 using idempotent guards so the state converges
-- correctly regardless of how 052 ended.

BEGIN;

-- ── Step 1: Drop FK constraints that reference endpoint_logs.id ──────────────
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

-- ── Step 2: Rename existing heap table to legacy if not already done ──────────
DO $$
BEGIN
    -- Only rename when endpoint_logs still exists as a plain heap (relkind='r')
    -- and endpoint_logs_legacy doesn't exist yet.
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'endpoint_logs_legacy' AND n.nspname = 'public'
    ) AND EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'endpoint_logs' AND n.nspname = 'public'
          AND c.relkind = 'r'   -- plain heap, not yet partitioned
    ) THEN
        ALTER TABLE endpoint_logs RENAME TO endpoint_logs_legacy;
    END IF;
END;
$$;

-- ── Step 3: Create the partitioned parent (idempotent) ────────────────────────
CREATE TABLE IF NOT EXISTS endpoint_logs (
    id           BIGSERIAL,
    agent_id     INTEGER,
    tenant_id    INTEGER,
    log_source   VARCHAR(100),
    log_message  TEXT,
    collected_at TIMESTAMP WITHOUT TIME ZONE DEFAULT now(),
    parsed_fields JSONB DEFAULT '{}'::jsonb,
    PRIMARY KEY (id, collected_at)
) PARTITION BY RANGE (collected_at);

-- ── Step 4: Attach legacy data as the default partition ───────────────────────
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'endpoint_logs_legacy' AND n.nspname = 'public'
    ) AND NOT EXISTS (
        SELECT 1 FROM pg_inherits
        WHERE inhparent = 'endpoint_logs'::regclass
          AND inhrelid  = 'endpoint_logs_legacy'::regclass
    ) THEN
        ALTER TABLE endpoint_logs ATTACH PARTITION endpoint_logs_legacy DEFAULT;
    END IF;
END;
$$;

-- ── Step 5: Pre-create current + next 3 months of partitions ─────────────────
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
            SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
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

-- ── Step 6: Indexes on the partitioned parent ─────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_el_tenant_collected
    ON endpoint_logs (tenant_id, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_el_agent_collected
    ON endpoint_logs (agent_id, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_el_parsed_fields_gin
    ON endpoint_logs USING GIN (parsed_fields);

-- ── Step 7: Partition maintenance function ────────────────────────────────────
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

COMMIT;
