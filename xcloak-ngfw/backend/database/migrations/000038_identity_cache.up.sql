-- Identity cache for AD/LDAP enrichment.
-- Populated by the LDAP service and refreshed periodically.
CREATE TABLE identity_cache (
    id             SERIAL PRIMARY KEY,
    tenant_id      BIGINT       NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    username       VARCHAR(255) NOT NULL,
    display_name   VARCHAR(255),
    email          VARCHAR(255),
    department     VARCHAR(255),
    title          VARCHAR(255),
    manager        VARCHAR(255),
    groups         TEXT[]       NOT NULL DEFAULT '{}',
    account_status VARCHAR(50)  NOT NULL DEFAULT 'unknown', -- active | disabled | locked | unknown
    last_logon     TIMESTAMPTZ,
    cached_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, username)
);

CREATE INDEX idx_identity_tenant      ON identity_cache (tenant_id);
CREATE INDEX idx_identity_email       ON identity_cache (email);
CREATE INDEX idx_identity_department  ON identity_cache (department);
