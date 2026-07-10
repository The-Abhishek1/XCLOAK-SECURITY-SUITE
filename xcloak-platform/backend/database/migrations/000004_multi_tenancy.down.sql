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
        EXECUTE format('DROP INDEX IF EXISTS idx_%I_tenant_id', t);
        EXECUTE format('ALTER TABLE %I DROP COLUMN IF EXISTS tenant_id', t);
    END LOOP;
END $$;

DROP TABLE IF EXISTS tenants;
