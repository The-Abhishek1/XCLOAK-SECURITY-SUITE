-- Migration: enhance endpoint_file_hashes table
-- Run this on your existing database.
-- Safe to run multiple times (uses IF NOT EXISTS / DO NOTHING patterns).

-- 1. Add new columns to endpoint_file_hashes
ALTER TABLE endpoint_file_hashes
    ADD COLUMN IF NOT EXISTS file_name   TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS file_size   BIGINT  NOT NULL DEFAULT 0;

-- 2. Add unique constraint on (agent_id, file_path) so upserts work.
--    Drop old duplicate rows first if they exist (keep most recent).
DELETE FROM endpoint_file_hashes a
USING endpoint_file_hashes b
WHERE a.id < b.id
  AND a.agent_id = b.agent_id
  AND a.file_path = b.file_path;

ALTER TABLE endpoint_file_hashes
    DROP CONSTRAINT IF EXISTS uq_agent_file_path;

ALTER TABLE endpoint_file_hashes
    ADD CONSTRAINT uq_agent_file_path UNIQUE (agent_id, file_path);

-- 3. Index on sha256 and md5 hashes for fast IOC lookups.
--    These are used in CheckFileHashIOC on every ingest batch.
CREATE INDEX IF NOT EXISTS idx_filehash_sha256
    ON endpoint_file_hashes (sha256_hash);

CREATE INDEX IF NOT EXISTS idx_filehash_md5
    ON endpoint_file_hashes (md5_hash);

CREATE INDEX IF NOT EXISTS idx_filehash_agent
    ON endpoint_file_hashes (agent_id);

-- 4. Extend the iocs table to support sha256 and md5 types.
--    The type column is TEXT so no schema change needed — just a reminder
--    that valid values are now: 'ip', 'sha256', 'md5'
-- (No schema change needed — adding this comment for documentation.)

-- Verify
SELECT
    column_name,
    data_type
FROM information_schema.columns
WHERE table_name = 'endpoint_file_hashes'
ORDER BY ordinal_position;
