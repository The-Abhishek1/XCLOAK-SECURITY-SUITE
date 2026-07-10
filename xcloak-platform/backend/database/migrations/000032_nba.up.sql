CREATE TABLE IF NOT EXISTS network_baselines (
    id          SERIAL PRIMARY KEY,
    agent_id    INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    dst_ip      VARCHAR(64)  NOT NULL,
    dst_port    INTEGER      NOT NULL,
    proto       VARCHAR(10)  NOT NULL DEFAULT 'tcp',
    hit_count   INTEGER      NOT NULL DEFAULT 1,
    first_seen  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (agent_id, dst_ip, dst_port, proto)
);

CREATE TABLE IF NOT EXISTS network_anomalies (
    id              SERIAL PRIMARY KEY,
    agent_id        INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    anomaly_type    VARCHAR(50)  NOT NULL, -- new_destination, rare_port, volume_spike, new_proto
    dst_ip          VARCHAR(64)  NOT NULL DEFAULT '',
    dst_port        INTEGER      NOT NULL DEFAULT 0,
    proto           VARCHAR(10)  NOT NULL DEFAULT 'tcp',
    deviation_score INTEGER      NOT NULL DEFAULT 0, -- 0-100
    description     TEXT         NOT NULL DEFAULT '',
    is_acknowledged BOOLEAN      NOT NULL DEFAULT false,
    detected_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_net_baselines_agent  ON network_baselines(agent_id);
CREATE INDEX IF NOT EXISTS idx_net_baselines_tenant ON network_baselines(tenant_id);
CREATE INDEX IF NOT EXISTS idx_net_anomalies_tenant ON network_anomalies(tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_net_anomalies_agent  ON network_anomalies(agent_id);
