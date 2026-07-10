-- Real-time outbound-connection events, sourced from the agent's eBPF
-- module (kprobe on tcp_v4_connect) — NOT a replacement for
-- endpoint_connections, which is a periodic snapshot of "what connections
-- exist right now" used by the live agent detail UI. This table is an
-- append-only forensic stream of "what connections happened," including
-- ones that opened and closed faster than the 5-minute snapshot poll could
-- ever see. Carries pid/comm/uid per connection — something the ss-based
-- snapshot collector can't reliably attribute to a process at all.

CREATE TABLE network_connect_events (
    id BIGSERIAL PRIMARY KEY,
    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id),
    pid INTEGER DEFAULT 0,
    comm VARCHAR(64) DEFAULT '',
    uid INTEGER DEFAULT 0,
    protocol VARCHAR(10) DEFAULT '',
    local_address TEXT DEFAULT '',
    remote_address TEXT DEFAULT '',
    state VARCHAR(20) DEFAULT '',
    event_ts BIGINT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_nce_agent_time ON network_connect_events (agent_id, created_at DESC);
CREATE INDEX idx_nce_remote ON network_connect_events (remote_address);
CREATE INDEX idx_nce_tenant ON network_connect_events (tenant_id);
