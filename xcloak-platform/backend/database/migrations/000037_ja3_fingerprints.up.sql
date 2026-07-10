-- JA3/JA3S TLS fingerprint blocklist.
-- tenant_id = NULL means platform-wide (applies to all tenants).
-- Tenant-specific rows override or extend the platform list.
CREATE TABLE ja3_fingerprints (
    id          SERIAL PRIMARY KEY,
    hash        CHAR(32)      NOT NULL,
    threat_name VARCHAR(255)  NOT NULL,
    severity    VARCHAR(20)   NOT NULL DEFAULT 'high',
    source      VARCHAR(100)  NOT NULL DEFAULT 'manual',
    description TEXT,
    enabled     BOOLEAN       NOT NULL DEFAULT TRUE,
    tenant_id   BIGINT        REFERENCES tenants(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- hash is unique per tenant (NULL tenant = platform-wide slot 0)
CREATE UNIQUE INDEX idx_ja3_hash_tenant ON ja3_fingerprints (hash, COALESCE(tenant_id, 0));
CREATE INDEX idx_ja3_tenant ON ja3_fingerprints (tenant_id);

-- Seed well-known malicious JA3 hashes (platform-wide, tenant_id = NULL).
-- Sources: abuse.ch ThreatFox, tls.fingerprint.io, public threat intel.
INSERT INTO ja3_fingerprints (hash, threat_name, severity, source, description, tenant_id) VALUES
  ('72a589da586844d7f0818ce684948eea', 'Cobalt Strike',        'critical', 'public-ti', 'Default Cobalt Strike Beacon ClientHello', NULL),
  ('a0e9f5d64349fb13191bc781f81f42e1', 'TrickBot',            'critical', 'public-ti', 'TrickBot C2 TLS fingerprint',              NULL),
  ('4d7a28d6f2263ed61de88ca66eb011e3', 'Emotet',              'critical', 'public-ti', 'Emotet loader TLS fingerprint',            NULL),
  ('bc6c386f480f687399573dc66c9b29a1', 'Dridex',              'critical', 'public-ti', 'Dridex banking trojan TLS fingerprint',    NULL),
  ('d4a2a3b03289b4a73b98036c30c46212', 'Metasploit',          'high',     'public-ti', 'Metasploit Meterpreter reverse_https',     NULL),
  ('eb78e08fd3f2f1cf2cbf9d86f5e44e4d', 'Sliver C2',           'critical', 'public-ti', 'Sliver implant default TLS profile',       NULL),
  ('c8f75cf4cca9280a0ed1b401c7eb27db', 'IcedID',              'critical', 'public-ti', 'IcedID (Bokbot) C2 TLS fingerprint',       NULL),
  ('b32309a26951912be7dba376398d2d3f', 'QakBot',              'critical', 'public-ti', 'QakBot loader TLS fingerprint',            NULL),
  ('b386946a5a44d1ddcc843bc75336dfce', 'AsyncRAT',            'high',     'public-ti', 'AsyncRAT C2 default TLS',                 NULL),
  ('c79dd966c5e56f2abf5adcdfac21a1b9', 'Havoc C2',            'critical', 'public-ti', 'Havoc Framework default Demon TLS',       NULL),
  ('e7d705a3286e19ea42f587b6c9f4f4f6', 'BruteRatel',          'critical', 'public-ti', 'BruteRatel C4 default profile',           NULL),
  ('51c64c77e60f3980eea90869b68c58a8', 'Nmap SSL Scan',       'low',      'public-ti', 'Nmap SSL/TLS version detection script',   NULL),
  ('6734f37431670b3ab4292b8f60f29984', 'Python requests',     'info',     'public-ti', 'Python-requests default TLS (benign baseline)', NULL);
