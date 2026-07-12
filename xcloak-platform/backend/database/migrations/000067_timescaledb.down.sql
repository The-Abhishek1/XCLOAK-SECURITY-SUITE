-- Reverting TimescaleDB hypertables back to plain tables is destructive
-- (data in compressed chunks cannot be selectively decompressed without
-- a full table rebuild). This down migration removes policies and the
-- extension but does NOT restore the original single-column PKs.
-- Restore from backup if you need the exact original schema.

DO $timescale$
DECLARE
  is_installed BOOLEAN;
BEGIN
  SELECT EXISTS (
    SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'
  ) INTO is_installed;

  IF NOT is_installed THEN
    RAISE NOTICE '[TimescaleDB] Extension not installed, nothing to revert';
    RETURN;
  END IF;

  -- Remove retention and compression policies (ignore if already missing)
  EXECUTE 'SELECT remove_retention_policy(''endpoint_connections'',   if_not_exists => TRUE)';
  EXECUTE 'SELECT remove_retention_policy(''endpoint_processes'',     if_not_exists => TRUE)';
  EXECUTE 'SELECT remove_compression_policy(''endpoint_connections'', if_not_exists => TRUE)';
  EXECUTE 'SELECT remove_compression_policy(''endpoint_processes'',   if_not_exists => TRUE)';

  -- Decompress all chunks so data is accessible after extension removal
  EXECUTE 'SELECT decompress_chunk(c) FROM show_chunks(''endpoint_connections'') c';
  EXECUTE 'SELECT decompress_chunk(c) FROM show_chunks(''endpoint_processes'')   c';

  RAISE NOTICE '[TimescaleDB] Policies removed and chunks decompressed';
END;
$timescale$;

DROP EXTENSION IF EXISTS timescaledb;
