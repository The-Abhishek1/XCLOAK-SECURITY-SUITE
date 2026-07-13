-- License key registry. The actual signed token is not stored here — only its
-- metadata so platform admins can list, audit, and revoke issued licenses.
-- The key_id embedded in the signed payload is what ties a token to this row.
CREATE TABLE IF NOT EXISTS license_keys (
    id             SERIAL PRIMARY KEY,
    key_id         TEXT        UNIQUE NOT NULL,
    customer_name  TEXT        NOT NULL,
    customer_email TEXT        NOT NULL,
    tier           TEXT        NOT NULL DEFAULT 'pro',
    agent_limit    INT         NOT NULL DEFAULT 25,
    user_limit     INT         NOT NULL DEFAULT 10,
    expires_at     TIMESTAMPTZ NOT NULL,
    revoked_at     TIMESTAMPTZ,
    revoke_reason  TEXT,
    notes          TEXT,
    created_by     TEXT        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- License enforcement toggle lives in the existing system_config k/v store.
-- key = 'license_mode', value = 'true' | 'false'
-- Inserted here so the row exists even before the first UI toggle.
INSERT INTO system_config (key, value)
VALUES ('license_mode', 'false')
ON CONFLICT (key) DO NOTHING;
