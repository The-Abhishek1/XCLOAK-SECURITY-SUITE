-- Supports the fleet-wide network map's tenant+time-range scan over
-- network_connect_events (existing indexes only cover agent_id+created_at,
-- remote_address, and tenant_id alone — none cover tenant_id+created_at).
-- Filters on created_at, not event_ts: event_ts is bpf_ktime_get_ns(), a
-- per-host CLOCK_MONOTONIC nanosecond reading since boot, not a wall-clock
-- timestamp — it's useless for cross-host/wall-clock time-window queries.
CREATE INDEX idx_nce_tenant_time ON network_connect_events (tenant_id, created_at DESC);
