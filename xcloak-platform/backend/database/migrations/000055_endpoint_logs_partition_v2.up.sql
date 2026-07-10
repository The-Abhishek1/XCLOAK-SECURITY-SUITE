-- Migration 055: Convert endpoint_logs heap table to a range-partitioned table.
--
-- This supersedes migration 052 which failed due to two issues:
--   1. Original endpoint_logs.id is INTEGER (int4); migration 052 used BIGSERIAL
--      (int8) for the new parent — PostgreSQL rejects the type mismatch at
--      ATTACH PARTITION time.
--   2. Original endpoint_logs PRIMARY KEY is (id); the partitioned parent
--      needs a PK of (id, collected_at) — the child must have a matching
--      unique constraint before it can be attached.
--
-- This migration fixes both issues:
--   • Creates the new partitioned parent with id SERIAL (int4, matching legacy).
--   • Adds a unique constraint on (id, collected_at) to the legacy table before
--     attaching it.
--
-- All steps are idempotent — safe to re-run if interrupted.

BEGIN;

-- ── Step 1: Drop FK constraints that reference endpoint_logs.id ──────────────
-- Partitioned tables do not support incoming foreign keys (PG 14 limitation).
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

-- ── Step 2: Rename existing heap table to legacy ──────────────────────────────
-- Only rename if endpoint_logs still exists as a plain heap (relkind='r')
-- and the legacy name is not already taken.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'endpoint_logs_legacy' AND n.nspname = 'public'
    ) AND EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'endpoint_logs' AND n.nspname = 'public'
          AND c.relkind = 'r'
    ) THEN
        ALTER TABLE endpoint_logs RENAME TO endpoint_logs_legacy;
    END IF;
END;
$$;

-- ── Step 3: Add (id, collected_at) unique constraint to the legacy table ──────
-- ATTACH PARTITION requires the child to have a constraint that satisfies the
-- parent's PRIMARY KEY (id, collected_at). We add it as a unique index-backed
-- constraint so it can be created WITHOUT TABLE LOCK on large tables.
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

-- ── Step 3b: Mark collected_at NOT NULL on the legacy table ──────────────────
-- PostgreSQL requires the partition key column to be NOT NULL in every child.
-- The original table defined collected_at as nullable; fill any NULLs first so
-- the ALTER doesn't fail on existing rows, then set the constraint.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'endpoint_logs_legacy' AND n.nspname = 'public'
    ) AND EXISTS (
        SELECT 1 FROM pg_attribute
        WHERE attrelid = 'endpoint_logs_legacy'::regclass
          AND attname   = 'collected_at'
          AND NOT attnotnull
    ) THEN
        UPDATE endpoint_logs_legacy SET collected_at = now() WHERE collected_at IS NULL;
        ALTER TABLE endpoint_logs_legacy ALTER COLUMN collected_at SET NOT NULL;
    END IF;
END;
$$;

-- ── Step 4: Create the partitioned parent ─────────────────────────────────────
-- id: SERIAL (int4) to match the original table's INTEGER type.
-- tenant_id: BIGINT NOT NULL DEFAULT 1 — migration 004 added this column as
--   BIGINT (not INTEGER) to all tenant-scoped tables, so migration 051's
--   ADD COLUMN IF NOT EXISTS tenant_id INTEGER was a no-op. ATTACH PARTITION
--   fails unless the parent's type matches the child's actual BIGINT type.
CREATE TABLE IF NOT EXISTS endpoint_logs (
    id            SERIAL,
    agent_id      INTEGER,
    tenant_id     BIGINT NOT NULL DEFAULT 1,
    log_source    VARCHAR(100),
    log_message   TEXT,
    collected_at  TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now(),
    parsed_fields JSONB DEFAULT '{}'::jsonb,
    PRIMARY KEY (id, collected_at)
) PARTITION BY RANGE (collected_at);

-- ── Step 5: Attach legacy data as the default partition ───────────────────────
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

-- ── Step 6: Pre-create current and next 3 monthly partitions ─────────────────
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

-- ── Step 7: Indexes on the partitioned parent (inherited by all partitions) ───
CREATE INDEX IF NOT EXISTS idx_el_tenant_collected
    ON endpoint_logs (tenant_id, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_el_agent_collected
    ON endpoint_logs (agent_id, collected_at DESC);

CREATE INDEX IF NOT EXISTS idx_el_parsed_fields_gin
    ON endpoint_logs USING GIN (parsed_fields);

COMMIT;
