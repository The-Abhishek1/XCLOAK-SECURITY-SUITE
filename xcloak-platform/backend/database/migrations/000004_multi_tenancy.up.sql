-- Multi-tenancy foundation. This is schema + auth scaffolding only —
-- enforcement (actually filtering queries by tenant_id) is only wired up
-- for agents/alerts/incidents as of this migration. Every other
-- tenant-scoped table below gets the column so a future pass doesn't need
-- another full-table migration, but nothing yet stops cross-tenant reads
-- on those tables. See security_roadmap memory / PR description for the
-- explicit list of what is and isn't enforced.

CREATE TABLE tenants (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO tenants (id, name, slug) VALUES (1, 'Default', 'default');
-- Keep the sequence consistent with the explicit id=1 insert above.
SELECT setval('tenants_id_seq', 1, true);

-- Every tenant-scoped table gets tenant_id NOT NULL DEFAULT 1 — existing
-- rows (and any insert path not yet updated to set it explicitly) land in
-- the Default tenant rather than failing or going NULL.
DO $$
DECLARE
    t TEXT;
    tenant_tables TEXT[] := ARRAY[
        'agents', 'agent_health', 'agent_heartbeats', 'agent_install_tokens', 'agent_tasks',
        'ai_chat_sessions', 'alert_metrics', 'alerts', 'anomaly_findings', 'asset_risk_scores',
        'audit_events', 'audit_logs', 'brute_force_state', 'collected_files',
        'compliance_reports', 'compliance_scores', 'correlation_rules',
        'email_alert_rules', 'endpoint_connections', 'endpoint_file_hashes', 'endpoint_logs',
        'endpoint_packages', 'endpoint_processes', 'endpoint_services', 'endpoint_users',
        'fim_alerts', 'fim_baselines', 'firewall_rules', 'firewall_sync_log',
        'hunt_queries', 'hunt_results', 'incident_events', 'incidents', 'integrations',
        'ioc_firewall_blocks', 'iocs', 'playbook_actions', 'playbook_executions', 'playbooks',
        'quarantined_files', 'registry_entries', 'scheduled_tasks', 'sigma_rules',
        'suppression_rules', 'suppression_state', 'threat_feeds', 'users', 'vulnerabilities',
        'webhook_deliveries', 'yara_matches', 'yara_rules'
    ];
BEGIN
    FOREACH t IN ARRAY tenant_tables LOOP
        EXECUTE format(
            'ALTER TABLE %I ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id)',
            t
        );
        EXECUTE format('CREATE INDEX idx_%I_tenant_id ON %I (tenant_id)', t, t);
    END LOOP;
END $$;

-- Not given tenant_id (deliberately): mitre_mappings, cve_cache, geoip_cache
-- (global reference data shared across all tenants), schema_migrations,
-- audit_export_cursor (infra/singleton state), rate_limit_events (dead
-- table, superseded by Redis-backed rate limiting in Phase 1).
