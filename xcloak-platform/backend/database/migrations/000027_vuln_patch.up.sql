ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS patch_status VARCHAR(30) NOT NULL DEFAULT 'open';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS patch_notes TEXT NOT NULL DEFAULT '';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS patched_at TIMESTAMPTZ;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS patch_sla_days INTEGER;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS priority_score INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_vuln_patch_status ON vulnerabilities(tenant_id, patch_status);
CREATE INDEX IF NOT EXISTS idx_vuln_priority ON vulnerabilities(tenant_id, priority_score DESC);
