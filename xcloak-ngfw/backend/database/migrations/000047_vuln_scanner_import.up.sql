-- Track each scanner file upload so the UI can show import history and status.
CREATE TABLE IF NOT EXISTS vuln_scan_imports (
    id          SERIAL PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    filename    TEXT    NOT NULL,
    scanner     TEXT    NOT NULL,           -- 'nessus', 'qualys', 'tenable'
    host_count  INTEGER NOT NULL DEFAULT 0,
    vuln_count  INTEGER NOT NULL DEFAULT 0,
    new_count   INTEGER NOT NULL DEFAULT 0, -- net-new rows inserted
    imported_by INTEGER REFERENCES users(id),
    imported_at TIMESTAMPTZ DEFAULT NOW(),
    error_msg   TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX idx_vuln_imports_tenant ON vuln_scan_imports (tenant_id, imported_at DESC);

-- Extend vulnerabilities with scanner-specific fields.
-- source distinguishes agent-reported vs. scanner-imported findings.
-- port/protocol identify network-visible services (key gap vs. pure agent coverage).
-- plugin_id is the scanner's internal check identifier (Nessus pluginID, Qualys QID).
-- import_id links back to the file upload record.
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS source    VARCHAR(50)  NOT NULL DEFAULT 'agent',
    ADD COLUMN IF NOT EXISTS port      INTEGER,
    ADD COLUMN IF NOT EXISTS protocol  VARCHAR(10),
    ADD COLUMN IF NOT EXISTS plugin_id VARCHAR(100) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS import_id INTEGER REFERENCES vuln_scan_imports(id);

-- Dedup index: one finding per (tenant, cve, plugin_id, port) regardless of agent.
-- agent_id can be NULL for network findings not matched to an endpoint.
-- A NULL cve_id is valid (plugin fires but no public CVE assigned yet); use plugin_id.
CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_scanner_dedup
    ON vulnerabilities (tenant_id, plugin_id, COALESCE(port, 0), COALESCE(cve_id, ''))
    WHERE source IN ('nessus', 'qualys', 'tenable');

CREATE INDEX IF NOT EXISTS idx_vuln_source ON vulnerabilities (tenant_id, source);
