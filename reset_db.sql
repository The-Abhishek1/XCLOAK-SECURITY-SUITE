-- ============================================================
-- XCloak Database Reset — wipes all operational data
-- Keeps: table structure, users (optional), sigma/yara rules
-- Run: docker exec -i <container_id> psql -U xcloak -d ngfw
-- ============================================================

-- ── Alert & detection data ────────────────────────────────────
TRUNCATE TABLE alerts                RESTART IDENTITY CASCADE;
TRUNCATE TABLE incidents             RESTART IDENTITY CASCADE;
TRUNCATE TABLE incident_events       RESTART IDENTITY CASCADE;

-- ── Agent telemetry ───────────────────────────────────────────
TRUNCATE TABLE endpoint_processes    RESTART IDENTITY CASCADE;
TRUNCATE TABLE endpoint_connections  RESTART IDENTITY CASCADE;
TRUNCATE TABLE endpoint_services     RESTART IDENTITY CASCADE;
TRUNCATE TABLE endpoint_packages     RESTART IDENTITY CASCADE;
TRUNCATE TABLE endpoint_users        RESTART IDENTITY CASCADE;
TRUNCATE TABLE endpoint_logs         RESTART IDENTITY CASCADE;
TRUNCATE TABLE endpoint_file_hashes  RESTART IDENTITY CASCADE;

-- ── Tasks ─────────────────────────────────────────────────────
TRUNCATE TABLE agent_tasks           RESTART IDENTITY CASCADE;

-- ── FIM ───────────────────────────────────────────────────────
TRUNCATE TABLE fim_baseline          RESTART IDENTITY CASCADE;
TRUNCATE TABLE fim_alerts            RESTART IDENTITY CASCADE;

-- ── Security events ───────────────────────────────────────────
TRUNCATE TABLE playbook_executions   RESTART IDENTITY CASCADE;
TRUNCATE TABLE quarantine_files      RESTART IDENTITY CASCADE;
TRUNCATE TABLE audit_logs            RESTART IDENTITY CASCADE;
TRUNCATE TABLE timeline_events       RESTART IDENTITY CASCADE;

-- ── AI data ───────────────────────────────────────────────────
TRUNCATE TABLE anomaly_findings      RESTART IDENTITY CASCADE;
TRUNCATE TABLE ai_chat_messages      RESTART IDENTITY CASCADE;

-- ── Vulnerability data ────────────────────────────────────────
TRUNCATE TABLE vulnerabilities       RESTART IDENTITY CASCADE;

-- ── Phase 7-11 tables ─────────────────────────────────────────
TRUNCATE TABLE hunt_results          RESTART IDENTITY CASCADE;
TRUNCATE TABLE alert_metrics         RESTART IDENTITY CASCADE;
TRUNCATE TABLE suppression_state     RESTART IDENTITY CASCADE;
TRUNCATE TABLE geoip_cache           RESTART IDENTITY CASCADE;
TRUNCATE TABLE agent_health          RESTART IDENTITY CASCADE;
TRUNCATE TABLE ioc_firewall_blocks   RESTART IDENTITY CASCADE;

-- ── Agents (keeps structure, re-register after reset) ─────────
-- Comment out if you want to keep agents registered:
TRUNCATE TABLE agents                RESTART IDENTITY CASCADE;

-- ── Optional: reset compliance reports ────────────────────────
TRUNCATE TABLE compliance_reports    RESTART IDENTITY CASCADE;

-- ── Keep these (rules, config, users): ───────────────────────
-- sigma_rules, yara_rules, iocs, firewall_rules, playbooks,
-- playbook_actions, threat_feeds, correlation_rules,
-- suppression_rules, scheduled_tasks, users

SELECT 'Database reset complete.' AS status;
SELECT table_name, 
       (xpath('/row/c/text()', query_to_xml(format('SELECT count(*) AS c FROM %I', table_name), false, true, '')))[1]::text::int AS row_count
FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;
