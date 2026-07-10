-- Insider threat scores: one row per (tenant, username, date).
-- Score 0–100; contributors are individual signal weights stored in jsonb.
CREATE TABLE IF NOT EXISTS insider_threat_scores (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   BIGINT      NOT NULL REFERENCES tenants(id),
    username    VARCHAR(255) NOT NULL,
    score_date  DATE        NOT NULL DEFAULT CURRENT_DATE,
    score       INT         NOT NULL DEFAULT 0 CHECK (score >= 0 AND score <= 100),
    risk_level  VARCHAR(20) NOT NULL DEFAULT 'low',  -- low / medium / high / critical
    contributors JSONB      NOT NULL DEFAULT '{}',   -- {"off_hours_auth":15, "data_exfil":30, ...}
    alert_fired BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, username, score_date)
);

CREATE INDEX idx_its_tenant_date   ON insider_threat_scores (tenant_id, score_date DESC);
CREATE INDEX idx_its_high_risk     ON insider_threat_scores (tenant_id, score DESC) WHERE score >= 60;
