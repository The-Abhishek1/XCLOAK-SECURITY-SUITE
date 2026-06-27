-- Self-reported health: heartbeat used to carry nothing but {"agent_id"},
-- so every "agent health" view was reconstructed entirely from heartbeat
-- timing and task outcomes with no signal from the agent's actual state.
ALTER TABLE agents ADD COLUMN version TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN uptime_seconds BIGINT NOT NULL DEFAULT 0;
ALTER TABLE agents ADD COLUMN mem_alloc_mb INT NOT NULL DEFAULT 0;
ALTER TABLE agents ADD COLUMN goroutines INT NOT NULL DEFAULT 0;

-- Self-update: one current release per platform (e.g. "linux_amd64"),
-- republishing overwrites it. Global/platform-admin-managed, not
-- tenant-scoped — the agent binary itself isn't tenant-specific.
CREATE TABLE agent_releases (
    id BIGSERIAL PRIMARY KEY,
    platform TEXT NOT NULL UNIQUE,
    version TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    download_url TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
