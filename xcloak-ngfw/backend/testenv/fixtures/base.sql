-- Base fixture data for integration tests.
-- Loaded after migrations run on the test database.
-- Every table truncates with CASCADE before inserting so tests can call
-- LoadFixtures multiple times without unique-constraint errors.

TRUNCATE tenants, agents, alerts, incidents, iocs, correlation_rules, endpoint_logs CASCADE;

-- ── Tenants ──────────────────────────────────────────────────────────────────
INSERT INTO tenants (id, name, is_active, log_retention_days)
VALUES
    (1, 'Acme Corp',    true, 90),
    (2, 'Beta LLC',     true, 30),
    (3, 'Inactive Co',  false, 30);

-- ── Agents ───────────────────────────────────────────────────────────────────
INSERT INTO agents (id, tenant_id, hostname, ip_address, os_type, status, last_seen, machine_id, agent_token)
VALUES
    (1, 1, 'web-01',    '10.0.1.1',  'linux',   'online',  NOW(), 'machine-aaa', 'tok-aaa'),
    (2, 1, 'db-01',     '10.0.1.2',  'windows', 'online',  NOW(), 'machine-bbb', 'tok-bbb'),
    (3, 2, 'tenant2-01','10.0.2.1',  'linux',   'offline', NOW() - INTERVAL '2 hours', 'machine-ccc', 'tok-ccc');

-- ── IOCs ─────────────────────────────────────────────────────────────────────
INSERT INTO iocs (id, tenant_id, type, indicator, severity, description, enabled)
VALUES
    (1, 1, 'ip',     '1.2.3.4',          'high',     'Known C2 server',          true),
    (2, 1, 'ip',     '192.168.100.0/24',  'medium',   'Suspicious subnet',        true),
    (3, 1, 'domain', 'evil.example.com',  'critical', 'Phishing domain',          true),
    (4, 1, 'url',    '/malware.exe',      'high',     'Malware download path',    true),
    (5, 1, 'ip',     '9.9.9.9',          'low',      'Disabled IOC',             false);

-- ── Correlation rules ─────────────────────────────────────────────────────────
INSERT INTO correlation_rules (id, tenant_id, name, rule_name, severity, mitre_technique, action, enabled, correlation_type, window_minutes, threshold, source_type, condition_value)
VALUES
    (1, 1, 'Brute Force Threshold', 'Failed password', 'medium', 'T1110', 'create_incident', true,  'event_count', 10, 5,  'alert', ''),
    (2, 1, 'Critical Alert Rule',   'Critical Alert',  'critical','',     'create_incident', true,  'simple',       0,  0,  'alert', ''),
    (3, 1, 'Disabled Rule',         'Any',             'low',     '',     'notify',          false, 'simple',       0,  0,  'alert', '');

-- ── Alerts ───────────────────────────────────────────────────────────────────
INSERT INTO alerts (id, agent_id, tenant_id, severity, rule_name, log_message, mitre_tactic, mitre_technique, fingerprint, created_at)
VALUES
    (1, 1, 1, 'high',     'IOC Match',          'IOC IP match: 1.2.3.4 → 1.2.3.4', 'Command and Control', 'T1071', 'ioc-ip-test-1', NOW()),
    (2, 1, 1, 'critical', 'Ransomware Detected', 'Mass file modification detected', 'Impact', 'T1486', 'ransom-test-1',   NOW()),
    (3, 2, 1, 'medium',   'Failed password',     'SSH brute force attempt',          'Credential Access', 'T1110', 'brute-test-1',  NOW());

-- ── Incidents ────────────────────────────────────────────────────────────────
INSERT INTO incidents (id, agent_id, tenant_id, title, severity, status, fingerprint)
VALUES
    (1, 1, 1, 'Active C2 Communication', 'high',     'open',     'incident-1-ioc-match'),
    (2, 1, 1, 'Possible Ransomware',     'critical', 'open',     'incident-1-ransomware-detected');

-- Reset sequences so future inserts don't collide with fixture IDs
SELECT setval('tenants_id_seq',    (SELECT MAX(id) FROM tenants));
SELECT setval('agents_id_seq',     (SELECT MAX(id) FROM agents));
SELECT setval('iocs_id_seq',       (SELECT MAX(id) FROM iocs));
SELECT setval('alerts_id_seq',     (SELECT MAX(id) FROM alerts));
SELECT setval('incidents_id_seq',  (SELECT MAX(id) FROM incidents));
SELECT setval('correlation_rules_id_seq', (SELECT MAX(id) FROM correlation_rules));
