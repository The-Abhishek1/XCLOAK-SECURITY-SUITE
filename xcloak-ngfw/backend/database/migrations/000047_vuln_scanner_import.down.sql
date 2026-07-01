DROP INDEX IF EXISTS idx_vuln_source;
DROP INDEX IF EXISTS idx_vuln_scanner_dedup;
ALTER TABLE vulnerabilities
    DROP COLUMN IF EXISTS import_id,
    DROP COLUMN IF EXISTS plugin_id,
    DROP COLUMN IF EXISTS protocol,
    DROP COLUMN IF EXISTS port,
    DROP COLUMN IF EXISTS source;
DROP TABLE IF EXISTS vuln_scan_imports;
