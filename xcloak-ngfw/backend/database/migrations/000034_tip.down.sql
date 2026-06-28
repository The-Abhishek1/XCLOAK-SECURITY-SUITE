DROP TABLE IF EXISTS alert_cluster_members;
DROP TABLE IF EXISTS alert_clusters;
DROP TABLE IF EXISTS feed_iocs;
ALTER TABLE threat_feeds
    DROP COLUMN IF EXISTS tenant_id,
    DROP COLUMN IF EXISTS format,
    DROP COLUMN IF EXISTS feed_weight,
    DROP COLUMN IF EXISTS api_key_enc,
    DROP COLUMN IF EXISTS ioc_count,
    DROP COLUMN IF EXISTS updated_at;
