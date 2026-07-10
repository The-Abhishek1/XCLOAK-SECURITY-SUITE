-- Mobile Device Management (MDM)
--
-- Five table groups:
--   1. mdm_devices          — enrolled device inventory
--   2. mdm_policies         — compliance policy definitions
--   3. mdm_policy_rules     — individual rules inside a policy
--   4. mdm_compliance_results — per-device, per-rule check outcomes
--   5. mdm_commands         — remote-action queue (lock/wipe/sync/push)
--   6. mdm_profiles         — configuration profiles (mobileconfig, OEMConfig, CSP)
--   7. mdm_profile_deployments — which profiles are on which devices

-- ── 1. Enrolled devices ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mdm_devices (
    id                  SERIAL PRIMARY KEY,
    tenant_id           INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id            INTEGER REFERENCES agents(id) ON DELETE SET NULL,

    -- Device identity
    udid                TEXT    NOT NULL,          -- UUID from MDM enroll
    serial_number       TEXT    NOT NULL DEFAULT '',
    device_name         TEXT    NOT NULL DEFAULT '',
    model               TEXT    NOT NULL DEFAULT '', -- "iPhone 15 Pro", "Pixel 8"
    platform            VARCHAR(20) NOT NULL CHECK (platform IN ('ios','android','windows','macos')),
    os_version          TEXT    NOT NULL DEFAULT '',
    build_version       TEXT    NOT NULL DEFAULT '',

    -- Ownership & enrollment
    owner_email         TEXT    NOT NULL DEFAULT '',
    enrollment_type     VARCHAR(30) NOT NULL DEFAULT 'user'
        CHECK (enrollment_type IN ('user','supervised','corporate','byod')),
    is_supervised       BOOLEAN NOT NULL DEFAULT FALSE,
    is_personal         BOOLEAN NOT NULL DEFAULT TRUE,
    enrolled_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_check_in       TIMESTAMPTZ,
    status              VARCHAR(20) NOT NULL DEFAULT 'enrolled'
        CHECK (status IN ('enrolled','unenrolled','blocked','pending')),

    -- Live security attributes (updated at each check-in)
    is_encrypted        BOOLEAN,
    has_passcode        BOOLEAN,
    passcode_compliant  BOOLEAN,
    is_jailbroken       BOOLEAN NOT NULL DEFAULT FALSE,
    developer_mode_on   BOOLEAN NOT NULL DEFAULT FALSE,
    firewall_enabled    BOOLEAN,

    -- Compliance rollup (recomputed by the compliance engine)
    compliance_status   VARCHAR(20) NOT NULL DEFAULT 'unknown'
        CHECK (compliance_status IN ('compliant','non_compliant','unknown')),
    compliance_checked_at TIMESTAMPTZ,

    -- Push delivery
    push_token          TEXT    NOT NULL DEFAULT '', -- APNS/FCM device token

    UNIQUE (tenant_id, udid)
);

CREATE INDEX idx_mdm_devices_tenant   ON mdm_devices (tenant_id, platform, status);
CREATE INDEX idx_mdm_devices_owner    ON mdm_devices (tenant_id, owner_email);
CREATE INDEX idx_mdm_devices_comply   ON mdm_devices (tenant_id, compliance_status);

-- ── 2. Compliance policies ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mdm_policies (
    id          SERIAL PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    -- Which platforms this policy applies to; empty = all
    platforms   TEXT[]  NOT NULL DEFAULT '{}',
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mdm_policies_tenant ON mdm_policies (tenant_id, is_active);

-- ── 3. Policy rules ──────────────────────────────────────────────────────────
-- rule_type values:
--   min_os_version        device os_version >= value (semver compare)
--   encryption_required   is_encrypted must be true
--   passcode_required     has_passcode must be true
--   passcode_min_length   passcode length >= value
--   screen_lock_max_min   screen lock timeout <= value minutes
--   jailbreak_not_allowed is_jailbroken must be false
--   developer_mode_off    developer_mode_on must be false
--   firewall_required     firewall_enabled must be true (macOS/Windows)
--   enrollment_type_req   enrollment_type must match value
--   app_not_installed     app with bundle_id == value must not be present
CREATE TABLE IF NOT EXISTS mdm_policy_rules (
    id          SERIAL PRIMARY KEY,
    policy_id   INTEGER NOT NULL REFERENCES mdm_policies(id) ON DELETE CASCADE,
    rule_type   TEXT    NOT NULL,
    value       TEXT    NOT NULL DEFAULT '',  -- threshold or expected value
    severity    VARCHAR(20) NOT NULL DEFAULT 'high'
        CHECK (severity IN ('critical','high','medium','low'))
);

CREATE INDEX idx_mdm_rules_policy ON mdm_policy_rules (policy_id);

-- ── 4. Compliance results ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mdm_compliance_results (
    id           SERIAL PRIMARY KEY,
    device_id    INTEGER NOT NULL REFERENCES mdm_devices(id) ON DELETE CASCADE,
    policy_id    INTEGER NOT NULL REFERENCES mdm_policies(id) ON DELETE CASCADE,
    rule_id      INTEGER NOT NULL REFERENCES mdm_policy_rules(id) ON DELETE CASCADE,
    status       VARCHAR(20) NOT NULL CHECK (status IN ('pass','fail','unknown')),
    actual_value TEXT    NOT NULL DEFAULT '',
    checked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (device_id, rule_id)
);

CREATE INDEX idx_mdm_compliance_device ON mdm_compliance_results (device_id, status);

-- ── 5. Command queue ─────────────────────────────────────────────────────────
-- command_type values: lock, wipe, sync, push_profile, remove_profile,
--                      install_app, remove_app, update_os, restart
CREATE TABLE IF NOT EXISTS mdm_commands (
    id               SERIAL PRIMARY KEY,
    tenant_id        INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id        INTEGER NOT NULL REFERENCES mdm_devices(id) ON DELETE CASCADE,
    command_type     TEXT    NOT NULL,
    payload          JSONB   NOT NULL DEFAULT '{}',
    status           VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','sent','acknowledged','failed','timed_out')),
    queued_by        INTEGER REFERENCES users(id),
    queued_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at          TIMESTAMPTZ,
    acknowledged_at  TIMESTAMPTZ,
    error_msg        TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX idx_mdm_commands_device ON mdm_commands (device_id, status, queued_at DESC);
CREATE INDEX idx_mdm_commands_tenant ON mdm_commands (tenant_id, status, queued_at DESC);

-- ── 6. Configuration profiles ────────────────────────────────────────────────
-- Stores iOS mobileconfig (XML), Android OEMConfig (JSON), Windows CSP (XML).
CREATE TABLE IF NOT EXISTS mdm_profiles (
    id           SERIAL PRIMARY KEY,
    tenant_id    INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,
    description  TEXT    NOT NULL DEFAULT '',
    platform     VARCHAR(20) NOT NULL CHECK (platform IN ('ios','android','windows','macos','all')),
    profile_type VARCHAR(30) NOT NULL DEFAULT 'config'
        CHECK (profile_type IN ('config','cert','vpn','wifi','email','passcode','restrictions')),
    content      TEXT    NOT NULL DEFAULT '',
    is_active    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mdm_profiles_tenant ON mdm_profiles (tenant_id, platform, is_active);

-- ── 7. Profile deployments ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mdm_profile_deployments (
    id           SERIAL PRIMARY KEY,
    profile_id   INTEGER NOT NULL REFERENCES mdm_profiles(id) ON DELETE CASCADE,
    device_id    INTEGER NOT NULL REFERENCES mdm_devices(id) ON DELETE CASCADE,
    status       VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','installed','failed','removed')),
    deployed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    installed_at TIMESTAMPTZ,
    error_msg    TEXT    NOT NULL DEFAULT '',
    UNIQUE (profile_id, device_id)
);
