-- Scheduled executive reports

CREATE TABLE IF NOT EXISTS scheduled_reports (
    id          SERIAL PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id),
    name        TEXT NOT NULL,
    report_type VARCHAR(50) NOT NULL DEFAULT 'executive',
    schedule    VARCHAR(100) NOT NULL DEFAULT '0 8 * * 1',
    recipients  TEXT[] NOT NULL DEFAULT '{}',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    last_sent_at TIMESTAMPTZ,
    created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sched_reports_tenant ON scheduled_reports(tenant_id);
