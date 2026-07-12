-- Key-value store for platform-level config (e.g. saas_mode toggle).
CREATE TABLE IF NOT EXISTS system_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Canonical plan definitions — seeded at startup, never modified by tenants.
CREATE TABLE IF NOT EXISTS plans (
    id           SERIAL PRIMARY KEY,
    name         TEXT    NOT NULL UNIQUE,   -- starter | growth | pro | enterprise
    display_name TEXT    NOT NULL,
    price_monthly NUMERIC(10,2) NOT NULL DEFAULT 0,
    max_agents   INT     NOT NULL DEFAULT 25,   -- -1 = unlimited
    max_users    INT     NOT NULL DEFAULT 5,    -- -1 = unlimited
    features     JSONB   NOT NULL DEFAULT '{}'
);

INSERT INTO plans (name, display_name, price_monthly, max_agents, max_users, features) VALUES
  ('trial',      'Free Trial',  0,      10,  3,  '{"dpi":false,"yara":false,"pdf_reports":false,"api_keys":false}'::jsonb),
  ('starter',    'Starter',     149,    25,  5,  '{"dpi":false,"yara":false,"pdf_reports":false,"api_keys":true}'::jsonb),
  ('growth',     'Growth',      399,    100, 15, '{"dpi":true,"yara":true,"pdf_reports":true,"api_keys":true}'::jsonb),
  ('pro',        'Pro',         999,    500, 50, '{"dpi":true,"yara":true,"pdf_reports":true,"api_keys":true,"sso":true}'::jsonb),
  ('enterprise', 'Enterprise',  0,      -1,  -1, '{"dpi":true,"yara":true,"pdf_reports":true,"api_keys":true,"sso":true,"custom_roles":true}'::jsonb)
ON CONFLICT (name) DO NOTHING;

-- One subscription row per tenant.
CREATE TABLE IF NOT EXISTS subscriptions (
    id                   SERIAL PRIMARY KEY,
    tenant_id            INT  NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
    plan_id              INT  NOT NULL REFERENCES plans(id),
    status               TEXT NOT NULL DEFAULT 'trial',  -- trial | active | suspended | cancelled
    trial_ends_at        TIMESTAMPTZ,
    current_period_start TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    current_period_end   TIMESTAMPTZ,
    stripe_customer_id   TEXT,
    stripe_subscription_id TEXT,
    notes                TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Auto-enroll existing tenants on the trial plan.
INSERT INTO subscriptions (tenant_id, plan_id, status, trial_ends_at)
SELECT t.id,
       (SELECT id FROM plans WHERE name = 'trial'),
       'trial',
       NOW() + INTERVAL '14 days'
FROM   tenants t
WHERE  NOT EXISTS (
    SELECT 1 FROM subscriptions s WHERE s.tenant_id = t.id
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_tenant ON subscriptions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions (status);
