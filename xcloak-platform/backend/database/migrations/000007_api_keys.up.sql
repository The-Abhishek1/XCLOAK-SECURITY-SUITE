-- Per-tenant API keys for programmatic access (scripts, CI/CD, automation),
-- as an auth path alongside JWT login. Only a SHA-256 hash of the key is
-- ever stored — unlike agent/install tokens (plaintext, looked up directly),
-- API keys are long-lived and meant to live in external scripts/pipelines,
-- so a DB read alone shouldn't hand over usable live credentials.
CREATE TABLE api_keys (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id),
    label TEXT NOT NULL DEFAULT '',
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    role TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);
