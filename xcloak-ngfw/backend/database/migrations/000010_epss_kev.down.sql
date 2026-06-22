DROP INDEX IF EXISTS idx_vulnerabilities_is_kev;
DROP TABLE IF EXISTS kev_cache;
DROP TABLE IF EXISTS epss_cache;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS kev_ransomware;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS kev_date_added;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS is_kev;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS epss_percentile;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS epss_score;
