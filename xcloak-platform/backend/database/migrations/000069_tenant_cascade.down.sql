-- Revert CASCADE back to NO ACTION for all tenant_id FKs added in 000069

ALTER TABLE agent_health              DROP CONSTRAINT agent_health_tenant_id_fkey,
                                      ADD  CONSTRAINT agent_health_tenant_id_fkey              FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE agent_heartbeats          DROP CONSTRAINT agent_heartbeats_tenant_id_fkey,
                                      ADD  CONSTRAINT agent_heartbeats_tenant_id_fkey          FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE agent_install_tokens      DROP CONSTRAINT agent_install_tokens_tenant_id_fkey,
                                      ADD  CONSTRAINT agent_install_tokens_tenant_id_fkey      FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE agent_tasks               DROP CONSTRAINT agent_tasks_tenant_id_fkey,
                                      ADD  CONSTRAINT agent_tasks_tenant_id_fkey               FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE agents                    DROP CONSTRAINT agents_tenant_id_fkey,
                                      ADD  CONSTRAINT agents_tenant_id_fkey                    FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE ai_chat_sessions          DROP CONSTRAINT ai_chat_sessions_tenant_id_fkey,
                                      ADD  CONSTRAINT ai_chat_sessions_tenant_id_fkey          FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE alert_investigation_cache DROP CONSTRAINT alert_investigation_cache_tenant_id_fkey,
                                      ADD  CONSTRAINT alert_investigation_cache_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE alert_metrics             DROP CONSTRAINT alert_metrics_tenant_id_fkey,
                                      ADD  CONSTRAINT alert_metrics_tenant_id_fkey             FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE alerts                    DROP CONSTRAINT alerts_tenant_id_fkey,
                                      ADD  CONSTRAINT alerts_tenant_id_fkey                    FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE anomaly_findings          DROP CONSTRAINT anomaly_findings_tenant_id_fkey,
                                      ADD  CONSTRAINT anomaly_findings_tenant_id_fkey          FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE api_keys                  DROP CONSTRAINT api_keys_tenant_id_fkey,
                                      ADD  CONSTRAINT api_keys_tenant_id_fkey                  FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE asset_risk_scores         DROP CONSTRAINT asset_risk_scores_tenant_id_fkey,
                                      ADD  CONSTRAINT asset_risk_scores_tenant_id_fkey         FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE assets                    DROP CONSTRAINT assets_tenant_id_fkey,
                                      ADD  CONSTRAINT assets_tenant_id_fkey                    FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE audit_events              DROP CONSTRAINT audit_events_tenant_id_fkey,
                                      ADD  CONSTRAINT audit_events_tenant_id_fkey              FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE audit_logs                DROP CONSTRAINT audit_logs_tenant_id_fkey,
                                      ADD  CONSTRAINT audit_logs_tenant_id_fkey                FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE brute_force_state         DROP CONSTRAINT brute_force_state_tenant_id_fkey,
                                      ADD  CONSTRAINT brute_force_state_tenant_id_fkey         FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE cases                     DROP CONSTRAINT cases_tenant_id_fkey,
                                      ADD  CONSTRAINT cases_tenant_id_fkey                     FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE collected_files           DROP CONSTRAINT collected_files_tenant_id_fkey,
                                      ADD  CONSTRAINT collected_files_tenant_id_fkey           FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE compliance_reports        DROP CONSTRAINT compliance_reports_tenant_id_fkey,
                                      ADD  CONSTRAINT compliance_reports_tenant_id_fkey        FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE compliance_scores         DROP CONSTRAINT compliance_scores_tenant_id_fkey,
                                      ADD  CONSTRAINT compliance_scores_tenant_id_fkey         FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE correlation_matches       DROP CONSTRAINT correlation_matches_tenant_id_fkey,
                                      ADD  CONSTRAINT correlation_matches_tenant_id_fkey       FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE correlation_rules         DROP CONSTRAINT correlation_rules_tenant_id_fkey,
                                      ADD  CONSTRAINT correlation_rules_tenant_id_fkey         FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE custom_roles              DROP CONSTRAINT custom_roles_tenant_id_fkey,
                                      ADD  CONSTRAINT custom_roles_tenant_id_fkey              FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE dpi_findings              DROP CONSTRAINT dpi_findings_tenant_id_fkey,
                                      ADD  CONSTRAINT dpi_findings_tenant_id_fkey              FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE email_alert_rules         DROP CONSTRAINT email_alert_rules_tenant_id_fkey,
                                      ADD  CONSTRAINT email_alert_rules_tenant_id_fkey         FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE endpoint_connections      DROP CONSTRAINT endpoint_connections_tenant_id_fkey,
                                      ADD  CONSTRAINT endpoint_connections_tenant_id_fkey      FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE endpoint_file_hashes      DROP CONSTRAINT endpoint_file_hashes_tenant_id_fkey,
                                      ADD  CONSTRAINT endpoint_file_hashes_tenant_id_fkey      FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE endpoint_logs_legacy      DROP CONSTRAINT endpoint_logs_tenant_id_fkey,
                                      ADD  CONSTRAINT endpoint_logs_tenant_id_fkey             FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE endpoint_packages         DROP CONSTRAINT endpoint_packages_tenant_id_fkey,
                                      ADD  CONSTRAINT endpoint_packages_tenant_id_fkey         FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE endpoint_processes        DROP CONSTRAINT endpoint_processes_tenant_id_fkey,
                                      ADD  CONSTRAINT endpoint_processes_tenant_id_fkey        FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE endpoint_services         DROP CONSTRAINT endpoint_services_tenant_id_fkey,
                                      ADD  CONSTRAINT endpoint_services_tenant_id_fkey         FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE endpoint_users            DROP CONSTRAINT endpoint_users_tenant_id_fkey,
                                      ADD  CONSTRAINT endpoint_users_tenant_id_fkey            FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE feed_sync_log             DROP CONSTRAINT feed_sync_log_tenant_id_fkey,
                                      ADD  CONSTRAINT feed_sync_log_tenant_id_fkey             FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE fim_alerts                DROP CONSTRAINT fim_alerts_tenant_id_fkey,
                                      ADD  CONSTRAINT fim_alerts_tenant_id_fkey                FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE fim_baselines             DROP CONSTRAINT fim_baselines_tenant_id_fkey,
                                      ADD  CONSTRAINT fim_baselines_tenant_id_fkey             FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE firewall_rules            DROP CONSTRAINT firewall_rules_tenant_id_fkey,
                                      ADD  CONSTRAINT firewall_rules_tenant_id_fkey            FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE firewall_sync_log         DROP CONSTRAINT firewall_sync_log_tenant_id_fkey,
                                      ADD  CONSTRAINT firewall_sync_log_tenant_id_fkey         FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE hunt_queries              DROP CONSTRAINT hunt_queries_tenant_id_fkey,
                                      ADD  CONSTRAINT hunt_queries_tenant_id_fkey              FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE hunt_results              DROP CONSTRAINT hunt_results_tenant_id_fkey,
                                      ADD  CONSTRAINT hunt_results_tenant_id_fkey              FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE incident_events           DROP CONSTRAINT incident_events_tenant_id_fkey,
                                      ADD  CONSTRAINT incident_events_tenant_id_fkey           FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE incidents                 DROP CONSTRAINT incidents_tenant_id_fkey,
                                      ADD  CONSTRAINT incidents_tenant_id_fkey                 FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE insider_threat_scores     DROP CONSTRAINT insider_threat_scores_tenant_id_fkey,
                                      ADD  CONSTRAINT insider_threat_scores_tenant_id_fkey     FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE integrations              DROP CONSTRAINT integrations_tenant_id_fkey,
                                      ADD  CONSTRAINT integrations_tenant_id_fkey              FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE ioc_firewall_blocks       DROP CONSTRAINT ioc_firewall_blocks_tenant_id_fkey,
                                      ADD  CONSTRAINT ioc_firewall_blocks_tenant_id_fkey       FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE iocs                      DROP CONSTRAINT iocs_tenant_id_fkey,
                                      ADD  CONSTRAINT iocs_tenant_id_fkey                      FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE network_connect_events    DROP CONSTRAINT network_connect_events_tenant_id_fkey,
                                      ADD  CONSTRAINT network_connect_events_tenant_id_fkey    FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE playbook_actions          DROP CONSTRAINT playbook_actions_tenant_id_fkey,
                                      ADD  CONSTRAINT playbook_actions_tenant_id_fkey          FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE playbook_executions       DROP CONSTRAINT playbook_executions_tenant_id_fkey,
                                      ADD  CONSTRAINT playbook_executions_tenant_id_fkey       FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE playbooks                 DROP CONSTRAINT playbooks_tenant_id_fkey,
                                      ADD  CONSTRAINT playbooks_tenant_id_fkey                 FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE quarantined_files         DROP CONSTRAINT quarantined_files_tenant_id_fkey,
                                      ADD  CONSTRAINT quarantined_files_tenant_id_fkey         FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE registry_entries          DROP CONSTRAINT registry_entries_tenant_id_fkey,
                                      ADD  CONSTRAINT registry_entries_tenant_id_fkey          FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE scheduled_reports         DROP CONSTRAINT scheduled_reports_tenant_id_fkey,
                                      ADD  CONSTRAINT scheduled_reports_tenant_id_fkey         FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE scheduled_tasks           DROP CONSTRAINT scheduled_tasks_tenant_id_fkey,
                                      ADD  CONSTRAINT scheduled_tasks_tenant_id_fkey           FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE sigma_rules               DROP CONSTRAINT sigma_rules_tenant_id_fkey,
                                      ADD  CONSTRAINT sigma_rules_tenant_id_fkey               FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE suppression_rules         DROP CONSTRAINT suppression_rules_tenant_id_fkey,
                                      ADD  CONSTRAINT suppression_rules_tenant_id_fkey         FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE suppression_state         DROP CONSTRAINT suppression_state_tenant_id_fkey,
                                      ADD  CONSTRAINT suppression_state_tenant_id_fkey         FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE threat_feeds              DROP CONSTRAINT threat_feeds_tenant_id_fkey,
                                      ADD  CONSTRAINT threat_feeds_tenant_id_fkey              FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE users                     DROP CONSTRAINT users_tenant_id_fkey,
                                      ADD  CONSTRAINT users_tenant_id_fkey                     FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE vulnerabilities           DROP CONSTRAINT vulnerabilities_tenant_id_fkey,
                                      ADD  CONSTRAINT vulnerabilities_tenant_id_fkey           FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE webhook_deliveries        DROP CONSTRAINT webhook_deliveries_tenant_id_fkey,
                                      ADD  CONSTRAINT webhook_deliveries_tenant_id_fkey        FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE yara_matches              DROP CONSTRAINT yara_matches_tenant_id_fkey,
                                      ADD  CONSTRAINT yara_matches_tenant_id_fkey              FOREIGN KEY (tenant_id) REFERENCES tenants(id);
ALTER TABLE yara_rules                DROP CONSTRAINT yara_rules_tenant_id_fkey,
                                      ADD  CONSTRAINT yara_rules_tenant_id_fkey                FOREIGN KEY (tenant_id) REFERENCES tenants(id);
