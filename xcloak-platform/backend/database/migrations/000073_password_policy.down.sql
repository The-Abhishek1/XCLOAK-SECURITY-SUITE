ALTER TABLE tenant_security_policy
    DROP COLUMN IF EXISTS min_password_length,
    DROP COLUMN IF EXISTS require_special_chars,
    DROP COLUMN IF EXISTS require_numbers,
    DROP COLUMN IF EXISTS password_expiry_days,
    DROP COLUMN IF EXISTS max_failed_logins,
    DROP COLUMN IF EXISTS lockout_duration_mins,
    DROP COLUMN IF EXISTS ip_allowlist;

ALTER TABLE users
    DROP COLUMN IF EXISTS password_changed_at;
