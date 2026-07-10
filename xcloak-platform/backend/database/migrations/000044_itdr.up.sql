-- Identity Threat Detection & Response (ITDR) findings table.
-- Each row is one discovered identity risk for a tenant, with evidence stored
-- as JSONB so different finding types can carry different context fields.

CREATE TABLE IF NOT EXISTS itdr_findings (
    id              SERIAL       PRIMARY KEY,
    tenant_id       INTEGER      NOT NULL,
    finding_type    TEXT         NOT NULL,  -- see itdr_service.go for full list
    severity        TEXT         NOT NULL,  -- low | medium | high | critical
    identity        TEXT         NOT NULL,  -- subject username / email / account
    identity_type   TEXT         NOT NULL DEFAULT 'endpoint', -- endpoint | portal | cloud
    source_ip       TEXT,
    description     TEXT         NOT NULL,
    evidence        JSONB        NOT NULL DEFAULT '{}',
    mitre_technique TEXT,
    status          TEXT         NOT NULL DEFAULT 'open', -- open | acknowledged | resolved | false_positive
    agent_id        INTEGER,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    -- dedup key: suppress duplicate findings for the same identity/type within 24h
    dedup_key       TEXT         NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_itdr_dedup
    ON itdr_findings (tenant_id, dedup_key)
    WHERE status NOT IN ('resolved', 'false_positive');

CREATE INDEX IF NOT EXISTS idx_itdr_tenant_status ON itdr_findings (tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_itdr_severity       ON itdr_findings (tenant_id, severity) WHERE status = 'open';
