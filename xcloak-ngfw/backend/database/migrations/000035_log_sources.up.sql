-- Log sources: external devices/systems that push logs to XCloak without
-- a deployed agent (firewalls via syslog, cloud services via HTTP webhook).
-- Each log source maps to a virtual agent row so all existing detection,
-- correlation, and alert code can reference it uniformly via agent_id.

CREATE TABLE IF NOT EXISTS log_sources (
    id           SERIAL PRIMARY KEY,
    tenant_id    INTEGER      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name         VARCHAR(200) NOT NULL,
    source_type  VARCHAR(50)  NOT NULL DEFAULT 'syslog', -- 'syslog' | 'http'
    ip_address   INET,                                   -- syslog: device IP
    api_key      VARCHAR(128) UNIQUE,                    -- http: SHA-256(secret)
    api_key_hint VARCHAR(16),                            -- display hint (prefix...)
    format       VARCHAR(30)  NOT NULL DEFAULT 'auto',   -- 'auto'|'syslog3164'|'syslog5424'|'cef'|'leef'|'json'
    device_type  VARCHAR(100),                           -- 'palo_alto'|'cisco_asa'|'fortinet'|'generic'|...
    agent_id     INTEGER REFERENCES agents(id) ON DELETE SET NULL,
    enabled      BOOLEAN      NOT NULL DEFAULT true,
    last_event   TIMESTAMPTZ,
    event_count  BIGINT       NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_log_sources_tenant   ON log_sources(tenant_id);
CREATE INDEX IF NOT EXISTS idx_log_sources_ip       ON log_sources(ip_address) WHERE ip_address IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_log_sources_ip_tenant
    ON log_sources(tenant_id, ip_address) WHERE ip_address IS NOT NULL;
