-- Enrollment tokens allow mobile devices to self-register without a user JWT.
-- An admin generates a token, shares it (or encodes it as a QR code), and the
-- device agent presents it to POST /api/mdm/self-enroll to receive an agent token.

CREATE TABLE mdm_enrollment_tokens (
    id         SERIAL PRIMARY KEY,
    tenant_id  INT  NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token      TEXT NOT NULL UNIQUE,
    label      TEXT NOT NULL DEFAULT '',
    platform   TEXT NOT NULL DEFAULT 'android', -- android | ios | any
    used_count INT  NOT NULL DEFAULT 0,
    max_uses   INT,           -- NULL = unlimited
    expires_at TIMESTAMPTZ,  -- NULL = never
    created_by INT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX ON mdm_enrollment_tokens(tenant_id);
CREATE INDEX ON mdm_enrollment_tokens(token);

-- App inventory snapshot for threat detection (sideloaded app detection, IOC match).
CREATE TABLE mdm_device_apps (
    id           SERIAL PRIMARY KEY,
    device_id    INT  NOT NULL REFERENCES mdm_devices(id) ON DELETE CASCADE,
    tenant_id    INT  NOT NULL,
    package_name TEXT NOT NULL,
    app_name     TEXT NOT NULL DEFAULT '',
    version      TEXT NOT NULL DEFAULT '',
    installer    TEXT NOT NULL DEFAULT '', -- empty = sideloaded; 'com.android.vending' = Play Store
    captured_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX ON mdm_device_apps(device_id);
CREATE INDEX ON mdm_device_apps(tenant_id, package_name);
