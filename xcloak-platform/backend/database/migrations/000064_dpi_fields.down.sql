DROP TABLE IF EXISTS dpi_findings;
ALTER TABLE network_connect_events
    DROP COLUMN IF EXISTS sni,
    DROP COLUMN IF EXISTS http_host,
    DROP COLUMN IF EXISTS http_method,
    DROP COLUMN IF EXISTS http_path,
    DROP COLUMN IF EXISTS http_user_agent,
    DROP COLUMN IF EXISTS tls_version,
    DROP COLUMN IF EXISTS tls_cipher,
    DROP COLUMN IF EXISTS dpi_proto,
    DROP COLUMN IF EXISTS entropy_score;
