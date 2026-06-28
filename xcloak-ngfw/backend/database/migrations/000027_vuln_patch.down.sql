ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS patch_status;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS patch_notes;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS patched_at;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS patch_sla_days;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS priority_score;
