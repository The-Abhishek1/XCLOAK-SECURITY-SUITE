-- Extend the existing threat_feeds table (it only has name/source/enabled/last_sync/created_at)
ALTER TABLE threat_feeds
    ADD COLUMN IF NOT EXISTS tenant_id    INTEGER REFERENCES tenants(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS format       VARCHAR(30) NOT NULL DEFAULT 'json',  -- json, csv, stix, misp
    ADD COLUMN IF NOT EXISTS feed_weight  INTEGER NOT NULL DEFAULT 70,          -- 0-100, used in IOC scoring
    ADD COLUMN IF NOT EXISTS api_key_enc  TEXT,                                 -- encrypted key if feed needs auth
    ADD COLUMN IF NOT EXISTS ioc_count    INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS updated_at   TIMESTAMPTZ DEFAULT NOW();

-- Feed-sourced IOCs (separate from manually-managed iocs table)
CREATE TABLE IF NOT EXISTS feed_iocs (
    id          SERIAL PRIMARY KEY,
    feed_id     INTEGER NOT NULL REFERENCES threat_feeds(id) ON DELETE CASCADE,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    indicator   TEXT    NOT NULL,
    ioc_type    VARCHAR(50) NOT NULL, -- ip, domain, url, hash_md5, hash_sha256, email
    confidence  INTEGER NOT NULL DEFAULT 70,
    score       INTEGER NOT NULL DEFAULT 70,
    tags        TEXT[]  NOT NULL DEFAULT '{}',
    description TEXT,
    expires_at  TIMESTAMPTZ,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(feed_id, indicator, ioc_type)
);

CREATE INDEX IF NOT EXISTS idx_feed_iocs_tenant     ON feed_iocs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_feed_iocs_indicator  ON feed_iocs(indicator);
CREATE INDEX IF NOT EXISTS idx_feed_iocs_type       ON feed_iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_feed_iocs_expires    ON feed_iocs(expires_at);

-- Alert clustering
CREATE TABLE IF NOT EXISTS alert_clusters (
    id              SERIAL PRIMARY KEY,
    tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    cluster_key     VARCHAR(512) NOT NULL,
    mitre_technique VARCHAR(20),
    rule_name       VARCHAR(255),
    alert_count     INTEGER NOT NULL DEFAULT 0,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    auto_incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    status          VARCHAR(30) NOT NULL DEFAULT 'open',  -- open, promoted, suppressed
    UNIQUE(tenant_id, cluster_key)
);

CREATE TABLE IF NOT EXISTS alert_cluster_members (
    cluster_id  INTEGER NOT NULL REFERENCES alert_clusters(id) ON DELETE CASCADE,
    alert_id    INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (cluster_id, alert_id)
);

CREATE INDEX IF NOT EXISTS idx_alert_clusters_tenant ON alert_clusters(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cluster_members_alert ON alert_cluster_members(alert_id);
