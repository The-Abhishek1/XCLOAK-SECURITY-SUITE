-- Case Management / IR Lifecycle

CREATE TABLE IF NOT EXISTS cases (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id),
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    severity        VARCHAR(20)  NOT NULL DEFAULT 'medium',
    status          VARCHAR(30)  NOT NULL DEFAULT 'open',
    phase           VARCHAR(30)  NOT NULL DEFAULT 'identification',
    assigned_to     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    assigned_to_name VARCHAR(255),
    sla_hours       INTEGER NOT NULL DEFAULT 24,
    sla_breach_at   TIMESTAMPTZ,
    sla_breached    BOOLEAN NOT NULL DEFAULT false,
    mitre_tactic    VARCHAR(100),
    mitre_technique VARCHAR(100),
    rca             TEXT,
    closed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS case_alerts (
    case_id  INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (case_id, alert_id)
);

CREATE TABLE IF NOT EXISTS case_incidents (
    case_id     INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (case_id, incident_id)
);

CREATE TABLE IF NOT EXISTS case_comments (
    id        SERIAL PRIMARY KEY,
    case_id   INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    user_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username  VARCHAR(255) NOT NULL,
    body      TEXT NOT NULL,
    is_system BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS case_evidence (
    id            SERIAL PRIMARY KEY,
    case_id       INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_type VARCHAR(50) NOT NULL,
    reference_id  INTEGER,
    title         TEXT NOT NULL,
    description   TEXT,
    added_by      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    added_by_name VARCHAR(255),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cases_tenant ON cases(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cases_status  ON cases(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_case_comments_case ON case_comments(case_id, created_at);
CREATE INDEX IF NOT EXISTS idx_case_evidence_case ON case_evidence(case_id);
