-- Adds real exploitability signal to vulnerability management: EPSS
-- (probability of exploitation in the next 30 days, from FIRST.org) and
-- CISA KEV (Known Exploited Vulnerabilities — confirmed active
-- exploitation, not just a theoretical CVSS score). A medium-CVSS CVE
-- that's in KEV is a higher real-world priority than a critical-CVSS one
-- that isn't — that distinction didn't exist before this migration.

ALTER TABLE vulnerabilities ADD COLUMN epss_score DOUBLE PRECISION DEFAULT 0;
ALTER TABLE vulnerabilities ADD COLUMN epss_percentile DOUBLE PRECISION DEFAULT 0;
ALTER TABLE vulnerabilities ADD COLUMN is_kev BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE vulnerabilities ADD COLUMN kev_date_added DATE;
ALTER TABLE vulnerabilities ADD COLUMN kev_ransomware BOOLEAN NOT NULL DEFAULT false;

-- Per-CVE EPSS cache (lazily populated, one row per CVE actually seen —
-- there are 200k+ CVEs total, no reason to bulk-fetch all of them).
CREATE TABLE epss_cache (
    cve_id TEXT PRIMARY KEY,
    epss_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    percentile DOUBLE PRECISION NOT NULL DEFAULT 0,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Full CISA KEV catalog mirror (~1600 entries as of 2026 — small enough to
-- refresh wholesale rather than per-CVE).
CREATE TABLE kev_cache (
    cve_id TEXT PRIMARY KEY,
    vendor_project TEXT DEFAULT '',
    product TEXT DEFAULT '',
    vulnerability_name TEXT DEFAULT '',
    date_added DATE,
    due_date DATE,
    known_ransomware BOOLEAN NOT NULL DEFAULT false,
    required_action TEXT DEFAULT '',
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_vulnerabilities_is_kev ON vulnerabilities (is_kev);
