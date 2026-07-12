-- TimescaleDB hypertable setup.
-- Safe to run against plain PostgreSQL — the DO block exits cleanly if the
-- extension is not installed (e.g. postgres:16-alpine).
-- To enable: switch to timescale/timescaledb-ha:pg16 and re-run migrations.
--
-- Tables converted to hypertables (high-volume telemetry):
--   endpoint_connections  (collected_at)  — 1-week chunks, 7-day compression
--   endpoint_processes    (collected_at)  — 1-week chunks, 7-day compression
--
-- NOT converted:
--   endpoint_logs  — already PARTITION BY RANGE (native); TimescaleDB cannot
--                    wrap a declaratively partitioned table. Native partitions
--                    remain managed by the partition_manager service.
--   alerts         — referenced by FK from incidents/cases; PK restructure
--                    would require cascading constraint changes.

DO $timescale$
DECLARE
  ts_available  BOOLEAN;
  is_hypertable BOOLEAN;
  ts_version    TEXT;
BEGIN
  SELECT EXISTS (
    SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb'
  ) INTO ts_available;

  IF NOT ts_available THEN
    RAISE NOTICE '[TimescaleDB] Extension not available on this server. Skipping.';
    RAISE NOTICE '[TimescaleDB] To enable HA telemetry compression + retention:';
    RAISE NOTICE '[TimescaleDB]   1. Switch image to timescale/timescaledb-ha:pg16';
    RAISE NOTICE '[TimescaleDB]   2. Re-run: go run . migrate  (or your migrate command)';
    RETURN;
  END IF;

  -- Enable extension (idempotent)
  EXECUTE 'CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE';
  EXECUTE 'SELECT extversion FROM pg_extension WHERE extname = ''timescaledb'''
    INTO ts_version;
  RAISE NOTICE '[TimescaleDB] v% enabled', ts_version;

  -- ── endpoint_connections ──────────────────────────────────────────────────
  EXECUTE 'SELECT EXISTS(SELECT 1 FROM _timescaledb_catalog.hypertable WHERE table_name = ''endpoint_connections'')'
    INTO is_hypertable;

  IF NOT is_hypertable THEN
    -- Drop integer-only PK — hypertable PKs must include the time column.
    ALTER TABLE endpoint_connections DROP CONSTRAINT IF EXISTS endpoint_connections_pkey;

    EXECUTE 'SELECT create_hypertable(
      ''endpoint_connections'', ''collected_at'',
      chunk_time_interval => INTERVAL ''1 week'',
      if_not_exists       => TRUE
    )';

    -- Recreate PK with time column included (required by TimescaleDB).
    ALTER TABLE endpoint_connections ADD PRIMARY KEY (id, collected_at);

    -- Compress chunks older than 7 days, ordered for fast time-range queries.
    EXECUTE 'ALTER TABLE endpoint_connections SET (
      timescaledb.compress,
      timescaledb.compress_orderby    = ''collected_at DESC'',
      timescaledb.compress_segmentby  = ''agent_id''
    )';
    EXECUTE 'SELECT add_compression_policy(''endpoint_connections'', INTERVAL ''7 days'')';

    -- Auto-drop data older than 90 days (adjust to your compliance window).
    EXECUTE 'SELECT add_retention_policy(''endpoint_connections'', INTERVAL ''90 days'', if_not_exists => TRUE)';

    RAISE NOTICE '[TimescaleDB] endpoint_connections → hypertable (1w chunks, 7d compression, 90d retention) ✓';
  ELSE
    RAISE NOTICE '[TimescaleDB] endpoint_connections already a hypertable, skipping';
  END IF;

  -- ── endpoint_processes ────────────────────────────────────────────────────
  EXECUTE 'SELECT EXISTS(SELECT 1 FROM _timescaledb_catalog.hypertable WHERE table_name = ''endpoint_processes'')'
    INTO is_hypertable;

  IF NOT is_hypertable THEN
    ALTER TABLE endpoint_processes DROP CONSTRAINT IF EXISTS endpoint_processes_pkey;

    EXECUTE 'SELECT create_hypertable(
      ''endpoint_processes'', ''collected_at'',
      chunk_time_interval => INTERVAL ''1 week'',
      if_not_exists       => TRUE
    )';

    ALTER TABLE endpoint_processes ADD PRIMARY KEY (id, collected_at);

    EXECUTE 'ALTER TABLE endpoint_processes SET (
      timescaledb.compress,
      timescaledb.compress_orderby    = ''collected_at DESC'',
      timescaledb.compress_segmentby  = ''agent_id''
    )';
    EXECUTE 'SELECT add_compression_policy(''endpoint_processes'', INTERVAL ''7 days'')';
    EXECUTE 'SELECT add_retention_policy(''endpoint_processes'', INTERVAL ''90 days'', if_not_exists => TRUE)';

    RAISE NOTICE '[TimescaleDB] endpoint_processes → hypertable (1w chunks, 7d compression, 90d retention) ✓';
  ELSE
    RAISE NOTICE '[TimescaleDB] endpoint_processes already a hypertable, skipping';
  END IF;

  RAISE NOTICE '[TimescaleDB] Setup complete ✓';
END;
$timescale$;
