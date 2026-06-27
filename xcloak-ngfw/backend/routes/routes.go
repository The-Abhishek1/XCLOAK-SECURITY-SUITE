package routes

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/api"
	"xcloak-ngfw/middleware"
)

func SetupRoutes(router *gin.Engine) {

	router.GET(
		"/api/health",
		api.Health,
	)

	// ── Firewall ──────────────────────────────────────────────────
	router.POST("/api/firewall/rules", middleware.RequireAuth(), api.CreateRule)
	router.GET("/api/firewall/rules", middleware.RequireAuth(), api.GetRules)
	router.GET("/api/firewall/rules/:id", middleware.RequireAuth(), api.GetRuleByID)
	router.PUT("/api/firewall/rules/:id", middleware.RequireAuth(), api.UpdateRule)
	router.DELETE("/api/firewall/rules/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_firewall"), api.DeleteRule)

	// ── Auth ──────────────────────────────────────────────────────
	router.POST("/api/auth/register", middleware.RateLimitAuth(), api.Register)
	router.POST("/api/auth/login", middleware.RateLimitAuth(), api.Login)

	// ── SSO (OIDC) ────────────────────────────────────────────────
	// Unauthenticated — these ARE the login entry point for a tenant's
	// configured identity provider.
	router.GET("/api/auth/oidc/start", middleware.RateLimitAuth(), api.StartOIDCLoginHandler)
	router.GET("/api/auth/oidc/callback", api.OIDCCallbackHandler)

	// ── Audit ─────────────────────────────────────────────────────
	router.GET("/api/audit/logs", middleware.RequireAuth(), api.GetAuditLogs)
	router.GET("/api/audit/logs/paginated", middleware.RequireAuth(), middleware.RateLimitAPI(), api.GetAuditLogsPaginatedHandler)
	router.GET("/api/audit/export/status", middleware.RequireAuth(), api.GetAuditExportStatusHandler)

	// ── Agents — STATIC routes MUST come before :id wildcard ─────
	router.POST("/api/agents/register", api.RegisterAgent)
	router.POST("/api/agents/heartbeat", middleware.RequireAgentAuth(), api.Heartbeat)
	router.POST("/api/agents/logs", middleware.RequireAgentAuth(), api.ReceiveLogs)
	router.POST("/api/agents/processes", middleware.RequireAgentAuth(), api.ReceiveProcesses)
	router.POST("/api/agents/audit-events", middleware.RequireAgentAuth(), api.ReceiveAuditEvents)
	router.POST("/api/agents/connect-events", middleware.RequireAgentAuth(), api.ReceiveConnectEvents)
	router.POST("/api/agents/registry", middleware.RequireAgentAuth(), api.ReceiveRegistry)
	router.POST("/api/agents/connections", middleware.RequireAgentAuth(), api.ReceiveConnections)
	router.POST("/api/agents/services", middleware.RequireAgentAuth(), api.ReceiveServices)
	router.POST("/api/agents/packages", middleware.RequireAgentAuth(), api.ReceivePackages)
	router.POST("/api/agents/users", middleware.RequireAgentAuth(), api.ReceiveUsers)
	router.POST("/api/agents/file", middleware.RequireAgentAuth(), api.ReceiveFile)
	router.POST("/api/agents/quarantine", middleware.RequireAgentAuth(), api.ReceiveQuarantinedFile)
	router.POST("/api/agents/fim", middleware.RequireAgentAuth(), api.ReceiveFIMScan)

	router.GET("/api/agents/health", middleware.RequireAuth(), api.GetAgentHealthScores)
	router.POST("/api/agents/health/refresh", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.RefreshAgentHealth)

	router.GET("/api/agents", middleware.RequireAuth(), api.GetAgents)

	// ── Agents — :id wildcard routes ─────────────────────────────
	router.GET("/api/agents/:id", middleware.RequireAuth(), api.GetAgentByID)
	router.GET("/api/agents/:id/summary", middleware.RequireAuth(), api.GetAgentSummary)
	router.GET("/api/agents/:id/risk", middleware.RequireAuth(), api.GetRiskScore)
	router.GET("/api/agents/:id/timeline", middleware.RequireAuth(), api.GetAgentTimeline)
	router.GET("/api/agents/:id/vulnerabilities", middleware.RequireAuth(), api.GetAgentVulnerabilities)
	router.POST("/api/agents/:id/vulnerability-scan", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.ScanAgentVulnerabilities)
	router.GET("/api/agents/:id/filehashes", middleware.RequireAuth(), api.GetAgentFileHashes)
	router.GET("/api/agents/:id/processes", middleware.RequireAuth(), api.GetAgentProcesses)
	router.GET("/api/agents/:id/connections", middleware.RequireAuth(), api.GetAgentConnections)
	router.GET("/api/agents/:id/audit-events", middleware.RequireAuth(), api.GetAuditEvents)
	router.GET("/api/agents/:id/connect-events", middleware.RequireAuth(), api.GetConnectEvents)
	router.GET("/api/agents/:id/registry", middleware.RequireAuth(), api.GetRegistryEntries)
	router.GET("/api/audit-events/threats", middleware.RequireAuth(), api.GetThreatAuditEvents)
	router.GET("/api/agents/:id/services", middleware.RequireAuth(), api.GetAgentServicesList)
	router.GET("/api/agents/:id/users", middleware.RequireAuth(), api.GetAgentUsersList)
	router.GET("/api/agents/:id/packages", middleware.RequireAuth(), api.GetAgentPackagesList)
	router.GET("/api/agents/:id/fim/baseline", middleware.RequireAuth(), api.GetFIMBaseline)
	router.POST("/api/agents/:id/fim/baseline/accept", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.AcceptFIMBaseline)
	router.GET("/api/agents/:id/fim/alerts", middleware.RequireAuth(), api.GetFIMAlerts)
	router.GET("/api/agents/:id/logs/stream", middleware.RequireAuth(), api.LiveLogsWS) // WS — was wrongly named LiveLogsSSE

	// ── Dashboard ─────────────────────────────────────────────────
	router.GET("/api/dashboard/overview", middleware.RequireAuth(), api.DashboardOverview)

	// ── Tasks ─────────────────────────────────────────────────────
	router.POST("/api/tasks", middleware.RequireAuth(), api.CreateTask)
	router.GET("/api/tasks/agent/:id", middleware.RequireAgentAuth(), api.GetAgentTasks)
	router.POST("/api/tasks/result", middleware.RequireAgentAuth(), api.SubmitTaskResult)
	router.GET("/api/tasks/pending-approval", middleware.RequireAuth(), api.GetPendingApprovalTasks)
	router.POST("/api/tasks/:id/approve", middleware.RequireAuth(), middleware.RequirePermission("approve_soar_actions"), api.ApproveTask)
	router.POST("/api/tasks/:id/reject", middleware.RequireAuth(), middleware.RequirePermission("approve_soar_actions"), api.RejectTask)

	// ── Alerts ───────────────────────────────────────────────────
	router.GET("/api/alerts", middleware.RequireAuth(), api.GetAlerts)
	router.GET("/api/alerts/paginated", middleware.RequireAuth(), middleware.RateLimitAPI(), api.GetAlertsPaginated)

	// ── Attack path graph ────────────────────────────────────────
	router.GET("/api/attack-path", middleware.RequireAuth(), api.GetAttackPathGraph)

	// ── Fleet-wide network map ───────────────────────────────────
	router.GET("/api/network-map", middleware.RequireAuth(), api.GetNetworkMap)

	// ── Incidents ────────────────────────────────────────────────
	router.GET("/api/incidents", middleware.RequireAuth(), api.GetIncidents)
	router.GET("/api/incidents/paginated", middleware.RequireAuth(), middleware.RateLimitAPI(), api.GetIncidentsPaginated)
	router.GET("/api/incidents/:id/events", middleware.RequireAuth(), api.GetIncidentEvents)
	router.PUT("/api/incidents/:id/status", middleware.RequireAuth(), api.UpdateIncidentStatus)

	// ── Quarantine ───────────────────────────────────────────────
	router.GET("/api/quarantine", middleware.RequireAuth(), api.GetQuarantinedFiles)

	// ── Sigma rules ──────────────────────────────────────────────
	router.POST("/api/sigma/rules", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.CreateSigmaRule)
	router.GET("/api/sigma/rules", middleware.RequireAuth(), api.GetSigmaRules)
	router.GET("/api/sigma/rules/:id", middleware.RequireAuth(), api.GetSigmaRuleByID)
	router.PUT("/api/sigma/rules/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.UpdateSigmaRule)
	router.DELETE("/api/sigma/rules/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.DeleteSigmaRule)
	router.PATCH("/api/sigma/rules/:id/enable", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.EnableSigmaRule)
	router.PATCH("/api/sigma/rules/:id/disable", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.DisableSigmaRule)
	router.POST("/api/sigma/rules/test", middleware.RequireAuth(), api.TestRules)

	// ── IOCs ──────────────────────────────────────────────────────
	router.POST("/api/iocs", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.CreateIOC)
	router.GET("/api/iocs", middleware.RequireAuth(), api.GetIOCs)
	router.GET("/api/iocs/:id", middleware.RequireAuth(), api.GetIOCByID)
	router.PUT("/api/iocs/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.UpdateIOC)
	router.DELETE("/api/iocs/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.DeleteIOC)
	router.PATCH("/api/iocs/:id/enable", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.EnableIOC)
	router.PATCH("/api/iocs/:id/disable", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.DisableIOC)
	router.POST("/api/iocs/import", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.ImportIOCs)

	// ── File hashes ───────────────────────────────────────────────
	router.POST("/api/filehashes", middleware.RequireAgentAuth(), api.SaveFileHashes)

	// ── Threat feeds ──────────────────────────────────────────────
	router.POST("/api/threat-feeds", middleware.RequireAuth(), middleware.RequirePermission("manage_threat_intel"), api.CreateThreatFeed)
	router.GET("/api/threat-feeds", middleware.RequireAuth(), api.GetThreatFeeds)
	router.POST("/api/threat-feeds/:id/sync", middleware.RequireAuth(), middleware.RequirePermission("manage_threat_intel"), api.SyncThreatFeed)

	// ── YARA ──────────────────────────────────────────────────────
	router.POST("/api/yara/matches", middleware.RequireAgentAuth(), api.ReceiveYaraMatches)
	router.GET("/api/yara/matches", middleware.RequireAuth(), api.GetYaraMatches)
	router.POST("/api/yara/rules", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.CreateYaraRule)
	router.GET("/api/yara/rules", middleware.RequireAuth(), api.GetYaraRules)
	router.GET("/api/yara/rules/enabled", middleware.RequireAgentAuth(), api.GetEnabledYaraRules)
	router.PUT("/api/yara/rules/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.UpdateYaraRule)
	router.DELETE("/api/yara/rules/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.DeleteYaraRule)
	router.PATCH("/api/yara/rules/:id/enable", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.EnableYaraRule)
	router.PATCH("/api/yara/rules/:id/disable", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.DisableYaraRule)

	// ── Playbooks ─────────────────────────────────────────────────
	router.POST("/api/playbooks", middleware.RequireAuth(), middleware.RequirePermission("manage_playbooks"), api.CreatePlaybook)
	router.GET("/api/playbooks", middleware.RequireAuth(), api.GetPlaybooks)
	router.PUT("/api/playbooks/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_playbooks"), api.UpdatePlaybook)
	router.DELETE("/api/playbooks/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_playbooks"), api.DeletePlaybook)
	router.PATCH("/api/playbooks/:id/enable", middleware.RequireAuth(), middleware.RequirePermission("manage_playbooks"), api.EnablePlaybook)
	router.PATCH("/api/playbooks/:id/disable", middleware.RequireAuth(), middleware.RequirePermission("manage_playbooks"), api.DisablePlaybook)
	router.GET("/api/playbooks/:id/actions", middleware.RequireAuth(), api.GetPlaybookActions)
	router.POST("/api/playbook-actions", middleware.RequireAuth(), middleware.RequirePermission("manage_playbooks"), api.CreatePlaybookAction)
	router.DELETE("/api/playbook-actions/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_playbooks"), api.DeletePlaybookAction)
	router.GET("/api/playbook-executions", middleware.RequireAuth(), api.GetPlaybookExecutions)
	router.GET("/api/playbook-executions/:id/steps", middleware.RequireAuth(), api.GetPlaybookStepResults)

	// ── Suppression ───────────────────────────────────────────────  ← WAS MISSING
	router.GET("/api/suppression/rules", middleware.RequireAuth(), api.GetSuppressionRules)
	router.POST("/api/suppression/rules", middleware.RequireAuth(), middleware.RequirePermission("manage_suppression"), api.CreateSuppressionRule)
	router.DELETE("/api/suppression/rules/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_suppression"), api.DeleteSuppressionRule)
	router.PATCH("/api/suppression/rules/:id/toggle", middleware.RequireAuth(), middleware.RequirePermission("manage_suppression"), api.ToggleSuppressionRule)

	// ── Compliance ────────────────────────────────────────────────
	router.POST("/api/compliance/reports", middleware.RequireAuth(), middleware.RequirePermission("manage_compliance"), api.GenerateReport)
	router.GET("/api/compliance/reports", middleware.RequireAuth(), api.GetReports)
	router.GET("/api/compliance/reports/:id", middleware.RequireAuth(), api.GetReport)
	router.GET("/api/compliance/reports/:id/pdf", middleware.RequireAuth(), api.GetReportPDF)
	router.DELETE("/api/compliance/reports/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_compliance"), api.DeleteReport)

	// ── Exports ───────────────────────────────────────────────────
	router.GET("/api/export/alerts", middleware.RequireAuth(), api.ExportAlertsCSV)
	router.GET("/api/export/incidents", middleware.RequireAuth(), api.ExportIncidentsCSV)
	router.GET("/api/export/vulnerabilities", middleware.RequireAuth(), api.ExportVulnerabilitiesCSV)
	router.GET("/api/export/audit", middleware.RequireAuth(), middleware.RequirePermission("export_audit_logs"), api.ExportAuditJSON)

	// ── CVE ───────────────────────────────────────────────────────
	router.GET("/api/cve/:id", middleware.RequireAuth(), api.GetCVEDetails)

	// ── Users ─────────────────────────────────────────────────────
	// Inviting a user or changing their role lets the caller grant ANY role,
	// including "admin" — these two stay true-admin-only (not delegable via
	// a custom permission) so a custom role with only manage_users can't be
	// used to mint a brand new admin and escalate beyond its own grant.
	router.GET("/api/users", middleware.RequireAuth(), middleware.RequirePermission("manage_users"), api.GetUsers)
	router.POST("/api/users/invite", middleware.RequireAuth(), middleware.RequireRole("admin"), api.InviteUserHandler)
	router.PUT("/api/users/:id/role", middleware.RequireAuth(), middleware.RequireRole("admin"), api.UpdateUserRole)
	router.PATCH("/api/users/:id/toggle", middleware.RequireAuth(), middleware.RequirePermission("manage_users"), api.ToggleUserActive)
	router.DELETE("/api/users/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_users"), api.DeleteUser)

	// ── API Keys (programmatic access) ──────────────────────────────
	// Same reasoning as invite/role above — creating a key lets the caller
	// pick its role, including admin, so creation stays true-admin-only.
	router.POST("/api/api-keys", middleware.RequireAuth(), middleware.RequireRole("admin"), api.CreateAPIKeyHandler)
	router.GET("/api/api-keys", middleware.RequireAuth(), middleware.RequirePermission("manage_api_keys"), api.GetAPIKeysHandler)
	router.DELETE("/api/api-keys/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_api_keys"), api.RevokeAPIKeyHandler)

	// ── Custom Roles (granular RBAC) ─────────────────────────────────
	router.GET("/api/permissions", middleware.RequireAuth(), api.GetPermissionsHandler)
	router.POST("/api/custom-roles", middleware.RequireAuth(), middleware.RequireRole("admin"), api.CreateCustomRoleHandler)
	router.GET("/api/custom-roles", middleware.RequireAuth(), middleware.RequireRole("admin"), api.GetCustomRolesHandler)
	router.PUT("/api/custom-roles/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.UpdateCustomRoleHandler)
	router.DELETE("/api/custom-roles/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.DeleteCustomRoleHandler)

	// ── Platform Admin (tenant provisioning) ────────────────────────
	router.POST("/api/platform/tenants", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.CreateTenantHandler)
	router.GET("/api/platform/tenants", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.GetTenantsHandler)
	router.PATCH("/api/platform/tenants/:id/toggle", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.ToggleTenantActiveHandler)
	router.POST("/api/platform/agent-releases", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.PublishAgentRelease)
	router.GET("/api/platform/agent-releases", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.GetAgentReleases)
	router.GET("/api/agent-releases/:platform", middleware.RequireAgentAuth(), api.GetLatestAgentRelease)

	// ── MITRE ─────────────────────────────────────────────────────
	router.GET("/api/mitre/mappings", middleware.RequireAuth(), api.GetMITREMappings)

	// ── Integrations ──────────────────────────────────────────────
	router.GET("/api/integrations", middleware.RequireAuth(), api.GetIntegrations)
	router.PUT("/api/integrations/:name", middleware.RequireAuth(), middleware.RequirePermission("manage_integrations"), api.SaveIntegration)
	router.POST("/api/integrations/:name/test", middleware.RequireAuth(), middleware.RequirePermission("manage_integrations"), api.TestIntegration)
	router.GET("/api/integrations/deliveries", middleware.RequireAuth(), api.GetWebhookDeliveries)
	router.GET("/api/integrations/install-tokens", middleware.RequireAuth(), middleware.RequirePermission("manage_integrations"), api.GetInstallTokens)
	router.POST("/api/integrations/install-tokens", middleware.RequireAuth(), middleware.RequirePermission("manage_integrations"), api.GenerateInstallToken)

	// ── AI ────────────────────────────────────────────────────────
	router.POST("/api/ai/triage/:id", middleware.RequireAuth(), api.TriageAlertHandler)
	router.POST("/api/ai/incidents/:id/summarize", middleware.RequireAuth(), api.SummarizeIncidentHandler)
	router.POST("/api/ai/anomaly/:agent_id", middleware.RequireAuth(), middleware.RequirePermission("run_ai_analysis"), api.RunAnomalyDetectionHandler)
	router.GET("/api/ai/anomalies", middleware.RequireAuth(), api.GetAnomaliesHandler)
	router.POST("/api/ai/chat", middleware.RequireAuth(), api.AIChatHandler)
	router.GET("/api/ai/chat/history", middleware.RequireAuth(), api.GetChatHistoryHandler)
	router.DELETE("/api/ai/chat/history", middleware.RequireAuth(), api.ClearChatHistoryHandler)

	// ── Behavioral threat detection ───────────────────────────────
	router.GET("/api/threat/scores", middleware.RequireAuth(), api.GetAnomalyScores)
	router.GET("/api/threat/fleet", middleware.RequireAuth(), api.GetFleetAnomalySummary)
	router.GET("/api/threat/baselines", middleware.RequireAuth(), api.GetAgentBaselines)
	router.POST("/api/threat/score/:agent_id", middleware.RequireAuth(), api.ScoreAgentNow)
	router.POST("/api/threat/findings/:id/acknowledge", middleware.RequireAuth(), api.AcknowledgeAnomalyFinding)

	// ── Log search, saved searches, retention ─────────────────────
	router.GET("/api/logs/search", middleware.RequireAuth(), api.SearchLogsHandler)
	router.GET("/api/logs/export", middleware.RequireAuth(), api.ExportLogs)
	router.GET("/api/logs/stats", middleware.RequireAuth(), api.GetLogStats)
	router.GET("/api/logs/searches", middleware.RequireAuth(), api.GetSavedLogSearches)
	router.POST("/api/logs/searches", middleware.RequireAuth(), api.SaveLogSearch)
	router.DELETE("/api/logs/searches/:id", middleware.RequireAuth(), api.DeleteSavedLogSearch)
	router.POST("/api/logs/searches/:id/run", middleware.RequireAuth(), api.RunSavedLogSearch)
	router.GET("/api/logs/retention", middleware.RequireAuth(), api.GetRetentionPolicy)
	router.PUT("/api/logs/retention", middleware.RequireAuth(), middleware.RequireRole("admin"), api.SetRetentionPolicy)

	// ── WebSocket notification stream (registered in main.go) ────
	// router.GET("/api/notifications/stream", ...) — kept in main.go

	// ── Auto-added missing routes ───────────────────────────
	router.GET("/api/agents/:id/tasks", middleware.RequireAuth(), api.GetAgentTaskHistory)
	router.GET("/api/agents/:id/auth-logs", middleware.RequireAuth(), api.GetAgentAuthLogs)
	router.GET("/api/agents/:id/risk/breakdown", middleware.RequireAuth(), api.GetAgentRiskBreakdown)
	router.GET("/api/scheduler/tasks", middleware.RequireAuth(), api.GetScheduledTasks)
	router.POST("/api/scheduler/tasks", middleware.RequireAuth(), middleware.RequirePermission("manage_scheduler"), api.CreateScheduledTask)
	router.PATCH("/api/scheduler/tasks/:id/toggle", middleware.RequireAuth(), middleware.RequirePermission("manage_scheduler"), api.ToggleScheduledTask)
	router.POST("/api/scheduler/tasks/:id/run", middleware.RequireAuth(), middleware.RequirePermission("manage_scheduler"), api.RunScheduledTaskNow)
	router.DELETE("/api/scheduler/tasks/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_scheduler"), api.DeleteScheduledTask)
	router.GET("/api/dashboard/metrics", middleware.RequireAuth(), api.GetDashboardMetrics)
	router.GET("/api/correlation/rules", middleware.RequireAuth(), api.GetCorrelationRules)
	router.POST("/api/correlation/rules", middleware.RequireAuth(), middleware.RequirePermission("manage_correlation_rules"), api.CreateCorrelationRule)
	router.PUT("/api/correlation/rules/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_correlation_rules"), api.UpdateCorrelationRule)
	router.PATCH("/api/correlation/rules/:id/toggle", middleware.RequireAuth(), middleware.RequirePermission("manage_correlation_rules"), api.ToggleCorrelationRule)
	router.DELETE("/api/correlation/rules/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_correlation_rules"), api.DeleteCorrelationRule)
	router.GET("/api/correlation/matches", middleware.RequireAuth(), api.GetCorrelationMatches)
	router.GET("/api/hunt/run", middleware.RequireAuth(), api.RunHunt)
	router.POST("/api/hunt/run", middleware.RequireAuth(), api.RunHunt)
	router.GET("/api/hunt/queries", middleware.RequireAuth(), api.GetHuntQueries)
	router.GET("/api/search", middleware.RequireAuth(), api.GlobalSearch)
	router.POST("/api/yara/import", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.ImportYARAFiles)
	router.POST("/api/sigma/import", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.ImportSigmaYAML)
	router.GET("/api/sigma/stats", middleware.RequireAuth(), api.GetSigmaStats)
	router.GET("/api/compliance/reports/:id/scores", middleware.RequireAuth(), api.GetComplianceFrameworkScores)
	router.POST("/api/incidents/:id/notes", middleware.RequireAuth(), api.AddIncidentNote)
	router.GET("/api/incidents/:id/deepdive", middleware.RequireAuth(), api.GetIncidentDeepDive)
	router.POST("/api/alerts/:id/acknowledge", middleware.RequireAuth(), api.AcknowledgeAlert)
	router.POST("/api/alerts/:id/resolve", middleware.RequireAuth(), api.ResolveAlert)
	router.POST("/api/alerts/bulk-acknowledge", middleware.RequireAuth(), api.BulkAcknowledgeAlerts)
	router.POST("/api/alerts/:id/respond", middleware.RequireAuth(), api.DispatchAlertResponse)
	router.GET("/api/alerts/:id", middleware.RequireAuth(), api.GetAlertWithTriage)
	router.POST("/api/iocs/bulk", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.BulkImportIOCs)
	router.POST("/api/firewall/sync", middleware.RequireAuth(), middleware.RequirePermission("sync_firewall"), api.SyncFirewallRules)
	router.GET("/api/firewall/sync/log", middleware.RequireAuth(), api.GetFirewallSyncLog)
	router.POST("/api/scripts/run", middleware.RequireAuth(), middleware.RequirePermission("run_scripts"), api.DispatchScript)
	router.GET("/api/scripts/result/:task_id", middleware.RequireAuth(), api.GetScriptResult)
	router.GET("/api/scripts/templates", middleware.RequireAuth(), api.GetScriptTemplates)
	router.GET("/api/scripts/history", middleware.RequireAuth(), api.GetScriptHistory)
	router.GET("/api/kafka/status", middleware.RequireAuth(), api.GetKafkaStatus)
	router.POST("/api/auth/logout", middleware.RequireAuth(), api.Logout)
	router.GET("/api/agents/me", middleware.RequireAgentAuth(), api.GetCurrentAgent)
	router.GET("/api/agents/:id/geo-stats", middleware.RequireAuth(), api.GetAgentGeoStats)
	router.POST("/api/agents/:id/enrich-connections", middleware.RequireAuth(), api.EnrichAgentConnections)
	router.GET("/api/agents/:id/health", middleware.RequireAuth(), api.GetAgentHealth)
	router.GET("/api/geoip/:ip", middleware.RequireAuth(), api.GetGeoIP)
	router.GET("/api/ioc-blocks", middleware.RequireAuth(), api.GetIOCBlocks)
	router.GET("/api/quarantine/stats", middleware.RequireAuth(), api.GetQuarantineStats)
	router.DELETE("/api/quarantine/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_quarantine"), api.ReleaseQuarantinedFile)
	router.POST("/api/quarantine", middleware.RequireAuth(), middleware.RequirePermission("manage_quarantine"), api.ReceiveQuarantinedFile)
	router.GET("/api/notifications/email", middleware.RequireAuth(), api.GetEmailRules)
	router.POST("/api/notifications/email", middleware.RequireAuth(), middleware.RequirePermission("manage_notifications"), api.CreateEmailRule)
	router.PATCH("/api/notifications/email/:id/toggle", middleware.RequireAuth(), middleware.RequirePermission("manage_notifications"), api.ToggleEmailRule)
	router.DELETE("/api/notifications/email/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_notifications"), api.DeleteEmailRule)
	router.POST("/api/auth/2fa/setup", middleware.RequireAuth(), api.Setup2FA)
	router.POST("/api/auth/2fa/verify", middleware.RequireAuth(), api.Verify2FA)
	router.DELETE("/api/auth/2fa", middleware.RequireAuth(), api.Disable2FA)
	router.GET("/api/auth/2fa/status", middleware.RequireAuth(), api.Get2FAStatus)
	router.POST("/api/auth/login/2fa", api.CompleteTOTPLogin)
	router.POST("/api/auth/forgot-password", api.ForgotPassword)
	router.POST("/api/auth/reset-password", api.ResetPassword)
	router.POST("/api/auth/change-password", middleware.RequireAuth(), api.ChangePassword)
	router.GET("/api/auth/profile", middleware.RequireAuth(), api.GetProfile)
	router.PATCH("/api/auth/profile", middleware.RequireAuth(), api.UpdateProfile)

}
