-- Settings' Authentication page (Password Policy / Login Protection) has
-- always let admins edit min_password_length, require_special_chars,
-- require_numbers, password_expiry_days, max_failed_logins,
-- lockout_duration_mins, and ip_allowlist, and showed a real-looking
-- "saved" confirmation on submit — but tenant_security_policy never had
-- these columns, so UpdateSecurityPolicy's ShouldBindJSON silently dropped
-- every one of them and nothing was ever enforced anywhere.
ALTER TABLE tenant_security_policy
    ADD COLUMN IF NOT EXISTS min_password_length INTEGER NOT NULL DEFAULT 8,
    ADD COLUMN IF NOT EXISTS require_special_chars BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS require_numbers BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS password_expiry_days INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS max_failed_logins INTEGER NOT NULL DEFAULT 5,
    ADD COLUMN IF NOT EXISTS lockout_duration_mins INTEGER NOT NULL DEFAULT 30,
    ADD COLUMN IF NOT EXISTS ip_allowlist TEXT NOT NULL DEFAULT '';

-- password_expiry_days needs a real "when was this password last set" clock
-- to expire against — users.created_at predates every password change, so
-- it's tracked separately here.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
