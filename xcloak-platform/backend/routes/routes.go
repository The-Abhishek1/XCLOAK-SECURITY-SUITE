package routes

import (
	"os"

	"github.com/gin-gonic/gin"

	"xcloak-platform/api"
	"xcloak-platform/middleware"
)

func SetupRoutes(router *gin.Engine) {

	// Health endpoints are exempt from the circuit breaker middleware
	// (they exist specifically to report circuit state).
	router.GET("/api/health", api.Health)
	router.GET("/api/health/deep", api.DeepHealth)

	// DB circuit breaker — returns 503 for all other endpoints when the
	// primary database is unreachable. Applied globally so it catches any
	// handler that touches the DB, without requiring per-handler checks.
	router.Use(middleware.DBCircuit())

	// SaaS guard — blocks suspended/expired tenants when SAAS_MODE is on.
	// No-op when tenant_id is not in context (unauthenticated / health routes).
	router.Use(middleware.SaasGuard())

	// ── Firewall ──────────────────────────────────────────────────
	router.POST("/api/firewall/rules", middleware.RequireAuth(), api.CreateRule)
	router.GET("/api/firewall/rules", middleware.RequireAuth(), api.GetRules)
	router.GET("/api/firewall/rules/:id", middleware.RequireAuth(), api.GetRuleByID)
	router.PUT("/api/firewall/rules/:id", middleware.RequireAuth(), api.UpdateRule)
	router.DELETE("/api/firewall/rules/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_firewall"), api.DeleteRule)

	// ── Demo ──────────────────────────────────────────────────────
	// No auth required — issues a short-lived read-only demo JWT.
	router.GET("/api/demo/start", middleware.RateLimitAuth(), api.DemoStart)

	// DemoReadOnly blocks mutations for demo sessions on all subsequent routes.
	router.Use(middleware.DemoReadOnly())

	// ── Auth ──────────────────────────────────────────────────────
	// In DEMO_ONLY mode these routes are blocked at the route level so that
	// the demo database stays free of real user accounts.
	if os.Getenv("DEMO_ONLY") != "true" {
		router.POST("/api/auth/register", middleware.RateLimitAuth(), api.Register)
		router.POST("/api/auth/login", middleware.RateLimitAuth(), api.Login)
		router.POST("/api/auth/refresh", middleware.RateLimitAuth(), api.RefreshToken)
		router.POST("/api/signup", middleware.RateLimitAuth(), api.Signup)
	}

	// ── SSO (OIDC) ────────────────────────────────────────────────
	// Unauthenticated — these ARE the login entry point for a tenant's
	// configured identity provider.
	router.GET("/api/auth/oidc/start", middleware.RateLimitAuth(), api.StartOIDCLoginHandler)
	router.GET("/api/auth/oidc/callback", api.OIDCCallbackHandler)
	router.GET("/api/auth/sso-discover", api.SSODiscover)

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

	router.GET("/api/agents", middleware.RequireAuth(), api.GetAgentsByPlatform)
	router.GET("/api/assets/platform-summary", middleware.RequireAuth(), api.GetPlatformSummary)

	// ── Agents — :id wildcard routes ─────────────────────────────
	router.GET("/api/agents/:id", middleware.RequireAuth(), api.GetAgentByID)
	router.GET("/api/agents/:id/summary", middleware.RequireAuth(), api.GetAgentSummary)
	router.GET("/api/agents/:id/risk", middleware.RequireAuth(), api.GetRiskScore)
	router.GET("/api/timeline", middleware.RequireAuth(), api.GetTenantTimeline)
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
	router.GET("/api/agents/:id/logs/stream", api.LiveLogsWS) // WS — auth via ?ticket= (see IssueWSTicket)
	router.POST("/api/agents/:id/rotate-token", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.RotateAgentTokenHandler)

	// ── Dashboard ─────────────────────────────────────────────────
	router.GET("/api/dashboard/overview", middleware.RequireAuth(), middleware.RateLimitAPI(), api.DashboardOverview)

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
	router.GET("/api/network-map/ip-info", middleware.RequireAuth(), api.GetIPInfo)
	router.GET("/api/network-map/port-info", middleware.RequireAuth(), api.GetPortInfoHandler)

	// ── Threat intelligence enrichment ───────────────────────────
	router.GET("/api/enrich/hash/:hash", middleware.RequireAuth(), api.GetHashEnrichment)
	router.PATCH("/api/settings/ioc-sharing", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.PatchTenantIOCSharing)

	// ── Incidents ────────────────────────────────────────────────
	router.GET("/api/incidents", middleware.RequireAuth(), api.GetIncidents)
	router.GET("/api/incidents/counts", middleware.RequireAuth(), api.GetIncidentStatusCounts)
	router.GET("/api/incidents/paginated", middleware.RequireAuth(), middleware.RateLimitAPI(), api.GetIncidentsPaginated)
	router.GET("/api/incidents/:id/events", middleware.RequireAuth(), api.GetIncidentEvents)
	router.GET("/api/incidents/:id/alerts", middleware.RequireAuth(), api.GetIncidentAlerts)
	router.PUT("/api/incidents/:id/status", middleware.RequireAuth(), api.UpdateIncidentStatus)
	router.PATCH("/api/incidents/:id/severity", middleware.RequireAuth(), api.UpdateIncidentSeverity)

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
	router.PATCH("/api/iocs/:id/shareable", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.PatchIOCShareable)

	// ── File hashes ───────────────────────────────────────────────
	router.POST("/api/filehashes", middleware.RequireAgentAuth(), api.SaveFileHashes)

	// ── Threat feeds ──────────────────────────────────────────────
	router.POST("/api/threat-feeds", middleware.RequireAuth(), middleware.RequirePermission("manage_threat_intel"), api.CreateThreatFeed)
	router.GET("/api/threat-feeds", middleware.RequireAuth(), api.GetThreatFeeds)
	router.PUT("/api/threat-feeds/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_threat_intel"), api.UpdateThreatFeed)
	router.DELETE("/api/threat-feeds/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_threat_intel"), api.DeleteThreatFeed)
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
	router.GET("/api/platform/tenants/:id/domains", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.GetTenantDomains)
	router.POST("/api/platform/tenants/:id/domains", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.AddTenantDomain)
	router.DELETE("/api/platform/tenants/:id/domains/:did", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.DeleteTenantDomain)
	router.POST("/api/platform/agent-releases", middleware.RequireAuthOrCIToken(), middleware.RequirePlatformAdmin(), api.PublishAgentRelease)
	router.GET("/api/platform/agent-releases", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.GetAgentReleases)
	router.GET("/api/agent-releases/:platform", middleware.RequireAgentAuth(), api.GetLatestAgentRelease)

	// ── SaaS Admin (platform admin only) ────────────────────────────
	router.GET("/api/platform/saas/mode", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.GetSaasModeHandler)
	router.POST("/api/platform/saas/mode", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.SetSaasModeHandler)
	router.GET("/api/platform/saas/stats", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.GetSaasStatsHandler)
	router.GET("/api/platform/saas/plans", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.GetAllPlansHandler)
	router.GET("/api/platform/saas/subscriptions", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.GetAllSubscriptionsHandler)
	router.PATCH("/api/platform/saas/subscriptions/:tenantID", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.UpdateSubscriptionHandler)

	// ── Tenant Billing (any authenticated user) ──────────────────────
	router.GET("/api/billing/subscription", middleware.RequireAuth(), api.GetMySubscriptionHandler)
	router.GET("/api/billing/plans", middleware.RequireAuth(), api.GetPlansHandler)
	router.POST("/api/billing/request-upgrade", middleware.RequireAuth(), api.RequestUpgradeHandler)

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
	router.GET("/api/logs/search", middleware.RequireAuth(), middleware.RateLimitAPI(), api.SearchLogsHandler)
	router.GET("/api/logs/export", middleware.RequireAuth(), middleware.RateLimitAPI(), api.ExportLogs)
	router.GET("/api/logs/stats", middleware.RequireAuth(), api.GetLogStats)
	router.GET("/api/logs/searches", middleware.RequireAuth(), api.GetSavedLogSearches)
	router.POST("/api/logs/searches", middleware.RequireAuth(), api.SaveLogSearch)
	router.DELETE("/api/logs/searches/:id", middleware.RequireAuth(), api.DeleteSavedLogSearch)
	router.POST("/api/logs/searches/:id/run", middleware.RequireAuth(), api.RunSavedLogSearch)
	router.GET("/api/logs/retention", middleware.RequireAuth(), api.GetRetentionPolicy)
	router.PUT("/api/logs/retention", middleware.RequireAuth(), middleware.RequireRole("admin"), api.SetRetentionPolicy)

	// ── Elasticsearch raw query interface ─────────────────────────
	router.POST("/api/elastic/query", middleware.RequireAuth(), middleware.RateLimitAPI(), api.ElasticQueryHandler)
	router.GET("/api/elastic/indices", middleware.RequireAuth(), api.ElasticIndicesHandler)
	router.GET("/api/elastic/mappings/:index", middleware.RequireAuth(), api.ElasticMappingsHandler)
	router.GET("/api/elastic/health", middleware.RequireAuth(), api.ElasticHealthHandler)

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
	router.GET("/api/dashboard/metrics", middleware.RequireAuth(), middleware.RateLimitAPI(), api.GetDashboardMetrics)
	router.GET("/api/correlation/rules", middleware.RequireAuth(), api.GetCorrelationRules)
	router.POST("/api/correlation/rules", middleware.RequireAuth(), middleware.RequirePermission("manage_correlation_rules"), api.CreateCorrelationRule)
	router.PUT("/api/correlation/rules/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_correlation_rules"), api.UpdateCorrelationRule)
	router.PATCH("/api/correlation/rules/:id/toggle", middleware.RequireAuth(), middleware.RequirePermission("manage_correlation_rules"), api.ToggleCorrelationRule)
	router.DELETE("/api/correlation/rules/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_correlation_rules"), api.DeleteCorrelationRule)
	router.GET("/api/correlation/matches", middleware.RequireAuth(), api.GetCorrelationMatches)
	router.GET("/api/hunt/run", middleware.RequireAuth(), api.RunHunt)
	router.POST("/api/hunt/run", middleware.RequireAuth(), api.RunHunt)
	router.GET("/api/hunt/queries", middleware.RequireAuth(), api.GetHuntQueries)
	router.POST("/api/hunt/queries/:id/run", middleware.RequireAuth(), api.RerunHuntQuery)
	router.DELETE("/api/hunt/queries/:id", middleware.RequireAuth(), api.DeleteHuntQuery)
	router.POST("/api/sigma/rules/from-hunt", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.PromoteHuntToSigmaRule)
	router.GET("/api/search", middleware.RequireAuth(), api.GlobalSearch)
	router.POST("/api/yara/import", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.ImportYARAFiles)
	router.POST("/api/sigma/import", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.ImportSigmaYAML)
	router.GET("/api/sigma/stats", middleware.RequireAuth(), api.GetSigmaStats)
	router.GET("/api/compliance/reports/:id/scores", middleware.RequireAuth(), api.GetComplianceFrameworkScores)
	router.POST("/api/incidents/:id/notes", middleware.RequireAuth(), api.AddIncidentNote)
	router.GET("/api/incidents/:id/deepdive", middleware.RequireAuth(), api.GetIncidentDeepDive)
	router.POST("/api/alerts/:id/acknowledge", middleware.RequireAuth(), api.AcknowledgeAlert)
	router.POST("/api/alerts/:id/resolve", middleware.RequireAuth(), api.ResolveAlert)
	router.PATCH("/api/alerts/:id/note", middleware.RequireAuth(), api.UpdateAlertNote)
	router.PATCH("/api/alerts/:id/snooze", middleware.RequireAuth(), api.SnoozeAlert)
	router.POST("/api/alerts/bulk-acknowledge", middleware.RequireAuth(), middleware.RateLimitAPI(), api.BulkAcknowledgeAlerts)
	router.POST("/api/alerts/:id/respond", middleware.RequireAuth(), api.DispatchAlertResponse)
	router.GET("/api/alerts/:id", middleware.RequireAuth(), api.GetAlertWithTriage)
	router.POST("/api/iocs/bulk", middleware.RequireAuth(), middleware.RateLimitAPI(), middleware.RequirePermission("manage_detection_rules"), api.BulkImportIOCs)
	router.POST("/api/firewall/sync", middleware.RequireAuth(), middleware.RequirePermission("sync_firewall"), api.SyncFirewallRules)
	router.GET("/api/firewall/sync/log", middleware.RequireAuth(), api.GetFirewallSyncLog)
	router.GET("/api/firewall/groups", middleware.RequireAuth(), api.GetFirewallGroups)
	router.GET("/api/firewall/stats", middleware.RequireAuth(), api.GetFirewallStats)
	router.GET("/api/firewall/conflicts", middleware.RequireAuth(), api.GetFirewallConflictsV2)
	router.GET("/api/firewall/policy", middleware.RequireAuth(), api.GetFirewallPolicy)
	router.PUT("/api/firewall/policy", middleware.RequireAuth(), middleware.RequirePermission("manage_firewall"), api.SetFirewallPolicy)
	router.POST("/api/firewall/rules/bulk", middleware.RequireAuth(), middleware.RequirePermission("manage_firewall"), api.BulkFirewallAction)
	router.POST("/api/firewall/rules/import", middleware.RequireAuth(), middleware.RequirePermission("manage_firewall"), api.ImportFirewallRules)
	router.GET("/api/firewall/templates", middleware.RequireAuth(), api.GetFirewallTemplates)
	router.GET("/api/firewall/expired", middleware.RequireAuth(), api.GetExpiredFirewallRules)
	router.DELETE("/api/firewall/expired", middleware.RequireAuth(), middleware.RequirePermission("manage_firewall"), api.PruneExpiredFirewallRules)
	router.POST("/api/agents/firewall-hits", middleware.RequireAgentAuth(), api.ReceiveFirewallHits)
	router.POST("/api/scripts/run", middleware.RequireAuth(), middleware.RequirePermission("run_scripts"), api.DispatchScript)
	router.GET("/api/scripts/result/:task_id", middleware.RequireAuth(), api.GetScriptResult)
	router.GET("/api/scripts/templates", middleware.RequireAuth(), api.GetScriptTemplates)
	router.GET("/api/scripts/history", middleware.RequireAuth(), api.GetScriptHistory)
	router.GET("/api/kafka/status", middleware.RequireAuth(), api.GetKafkaStatus)
	router.POST("/api/auth/logout", middleware.RequireAuth(), api.Logout)
	router.GET("/api/agents/me", middleware.RequireAgentAuth(), api.GetCurrentAgent)
	router.GET("/api/agents/self/summary",  middleware.RequireAgentAuth(), api.GetSelfSummary)
	router.GET("/api/agents/self/alerts",   middleware.RequireAgentAuth(), api.GetSelfAlerts)
	router.GET("/api/agents/self/timeline", middleware.RequireAgentAuth(), api.GetSelfTimeline)
	router.GET("/api/agents/self/tasks",    middleware.RequireAgentAuth(), api.GetSelfTasks)
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
	router.POST("/api/auth/oidc/exchange", api.OIDCTokenExchange)
	router.POST("/api/ws/ticket", middleware.RequireAuth(), api.IssueWSTicket)
	router.POST("/api/auth/change-password", middleware.RequireAuth(), api.ChangePassword)
	router.GET("/api/auth/profile", middleware.RequireAuth(), api.GetProfile)
	router.PATCH("/api/auth/profile", middleware.RequireAuth(), api.UpdateProfile)

	// ── Case Management / IR Lifecycle ────────────────────────────────────
	router.POST("/api/cases", middleware.RequireAuth(), api.CreateCase)
	router.GET("/api/cases", middleware.RequireAuth(), api.GetCases)
	router.GET("/api/cases/:id", middleware.RequireAuth(), api.GetCaseByID)
	router.PUT("/api/cases/:id", middleware.RequireAuth(), api.UpdateCase)
	router.DELETE("/api/cases/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_incidents"), api.DeleteCase)
	router.POST("/api/cases/:id/comments", middleware.RequireAuth(), api.AddCaseComment)
	router.POST("/api/cases/:id/evidence", middleware.RequireAuth(), api.AddCaseEvidence)
	router.POST("/api/cases/:id/alerts", middleware.RequireAuth(), api.LinkAlertToCase)
	router.DELETE("/api/cases/:id/alerts/:alert_id", middleware.RequireAuth(), api.UnlinkAlertFromCase)

	// ── Asset Management (CMDB) ───────────────────────────────────────────
	router.GET("/api/assets", middleware.RequireAuth(), api.GetAssets)
	router.POST("/api/assets", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.CreateAsset)
	router.GET("/api/assets/:id", middleware.RequireAuth(), api.GetAssetByID)
	router.PUT("/api/assets/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.UpdateAsset)
	router.DELETE("/api/assets/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.DeleteAsset)

	// ── Executive Dashboard + Scheduled Reports ───────────────────────────
	router.GET("/api/executive/metrics", middleware.RequireAuth(), api.GetExecutiveMetrics)
	router.GET("/api/executive/report/download", middleware.RequireAuth(), api.DownloadExecutiveReport)
	router.GET("/api/scheduled-reports", middleware.RequireAuth(), api.GetScheduledReports)
	router.POST("/api/scheduled-reports", middleware.RequireAuth(), middleware.RequirePermission("manage_notifications"), api.CreateScheduledReport)
	router.PUT("/api/scheduled-reports/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_notifications"), api.UpdateScheduledReport)
	router.DELETE("/api/scheduled-reports/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_notifications"), api.DeleteScheduledReport)

	// ── UEBA (User/Entity Behavior Analytics) ────────────────────────────
	router.GET("/api/ueba/users", middleware.RequireAuth(), api.GetUEBAUsers)
	router.GET("/api/ueba/events", middleware.RequireAuth(), api.GetUEBAEvents)
	router.POST("/api/ueba/analyze", middleware.RequireAuth(), middleware.RequirePermission("run_ai_analysis"), api.TriggerUEBAAnalysis)

	// ── Session Management ────────────────────────────────────────────────
	router.GET("/api/auth/sessions", middleware.RequireAuth(), api.GetMySessions)
	router.GET("/api/sessions", middleware.RequireAuth(), middleware.RequirePermission("manage_users"), api.GetAllSessions)
	router.DELETE("/api/sessions/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_users"), api.RevokeSession)

	// ── Security Policy ───────────────────────────────────────────────────
	router.GET("/api/security-policy", middleware.RequireAuth(), api.GetSecurityPolicy)
	router.PUT("/api/security-policy", middleware.RequireAuth(), middleware.RequireRole("admin"), api.UpdateSecurityPolicy)

	// ── Threat feed sync log ──────────────────────────────────────────────
	router.GET("/api/threat-feeds/:id/sync-log", middleware.RequireAuth(), api.GetFeedSyncLog)

	// ── Vulnerability priority queue ──────────────────────────────────────
	router.GET("/api/vulns/priority-queue", middleware.RequireAuth(), api.GetVulnPriorityQueue)
	router.POST("/api/vulns/refresh-priorities", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.RefreshVulnPriorities)
	router.PATCH("/api/vulns/:id/patch-status", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.UpdateVulnPatchStatus)

	// ── Scanner XML import (Nessus / Qualys / Tenable.sc) ────────────────
	router.POST("/api/vulns/import", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.ImportVulnScan)
	router.GET("/api/vulns/imports", middleware.RequireAuth(), api.ListVulnImports)

	// ── SOC analyst performance ───────────────────────────────────────────
	router.GET("/api/soc/metrics", middleware.RequireAuth(), api.GetSOCMetrics)

	// ── Alert investigation context ───────────────────────────────────────
	router.GET("/api/alerts/:id/investigate", middleware.RequireAuth(), api.GetAlertInvestigation)

	// ── Deception Technology ──────────────────────────────────────────────
	router.GET("/api/canary/tokens", middleware.RequireAuth(), api.ListCanaryTokens)
	router.POST("/api/canary/tokens", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.CreateCanaryToken)
	router.DELETE("/api/canary/tokens/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.DeleteCanaryToken)
	router.PATCH("/api/canary/tokens/:id/toggle", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.ToggleCanaryToken)
	router.GET("/api/canary/trips", middleware.RequireAuth(), api.GetCanaryTrips)
	router.GET("/api/canary/trip/:value", api.TripCanaryToken) // public — embedded in docs/URLs
	router.GET("/api/honeyports", middleware.RequireAuth(), api.ListHoneyports)
	router.POST("/api/honeyports", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.CreateHoneyport)
	router.DELETE("/api/honeyports/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.DeleteHoneyport)

	// ── Risk Posture Score ────────────────────────────────────────────────
	router.GET("/api/risk-posture", middleware.RequireAuth(), api.GetRiskPosture)
	router.GET("/api/risk-posture/history", middleware.RequireAuth(), api.GetRiskPostureHistoryHandler)
	router.POST("/api/risk-posture/refresh", middleware.RequireAuth(), middleware.RequirePermission("run_ai_analysis"), api.RefreshRiskPosture)

	// ── Hunt Workbench ────────────────────────────────────────────────────
	router.GET("/api/hunt/templates", middleware.RequireAuth(), api.ListHuntTemplates)
	router.POST("/api/hunt/templates", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.CreateHuntTemplate)
	router.DELETE("/api/hunt/templates/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.DeleteHuntTemplate)
	router.GET("/api/hunt/runs", middleware.RequireAuth(), api.ListHuntRuns)
	router.GET("/api/hunt/runs/:id", middleware.RequireAuth(), api.GetHuntRunDetail)
	router.POST("/api/hunt/execute", middleware.RequireAuth(), api.ExecuteHunt)
	router.PATCH("/api/hunt/runs/:id/notes", middleware.RequireAuth(), api.UpdateHuntRunNotes)

	// ── Threat Actor Intelligence ─────────────────────────────────────────────
	router.GET("/api/threat-actors", middleware.RequireAuth(), api.ListThreatActors)
	router.POST("/api/threat-actors", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.CreateThreatActor)
	router.DELETE("/api/threat-actors/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.DeleteThreatActor)
	router.GET("/api/threat-actors/:id/alerts", middleware.RequireAuth(), api.GetActorAlerts)
	router.GET("/api/alerts/:id/actor-tags", middleware.RequireAuth(), api.GetAlertActorTags)

	// ── Playbook Recommender ──────────────────────────────────────────────────
	router.GET("/api/alerts/:id/playbook-recommendations", middleware.RequireAuth(), api.GetPlaybookRecommendations)
	router.POST("/api/alerts/:id/execute-recommendation", middleware.RequireAuth(), api.ExecuteRecommendedPlaybook)

	// ── Network Behavior Analytics ────────────────────────────────────────────
	router.GET("/api/nba/anomalies", middleware.RequireAuth(), api.GetNetworkAnomalies)
	router.POST("/api/nba/anomalies/:id/acknowledge", middleware.RequireAuth(), api.AcknowledgeNetworkAnomaly)
	router.GET("/api/nba/baseline/:agent_id", middleware.RequireAuth(), api.GetNetworkBaselineStats)
	router.POST("/api/nba/analyze", middleware.RequireAuth(), middleware.RequirePermission("run_ai_analysis"), api.TriggerNBAAnalysis)

	// ── DFIR ──────────────────────────────────────────────────────────────────
	router.GET("/api/dfir/collections", middleware.RequireAuth(), api.ListForensicCollections)
	router.POST("/api/dfir/collections", middleware.RequireAuth(), middleware.RequirePermission("run_ai_analysis"), api.TriggerForensicCollection)
	router.GET("/api/dfir/collections/:id/artifacts", middleware.RequireAuth(), api.GetCollectionArtifacts)
	router.GET("/api/dfir/incidents/:incident_id/timeline", middleware.RequireAuth(), api.GetForensicTimeline)

	// ── EDR Response depth ────────────────────────────────────────────────────
	router.POST("/api/agents/:id/memory-dump", middleware.RequireAuth(), middleware.RequirePermission("run_ai_analysis"), api.DispatchMemoryDump)
	router.POST("/api/agents/:id/process-snapshot", middleware.RequireAuth(), api.DispatchProcessSnapshot)
	router.POST("/api/agents/:id/kill-tree", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.DispatchKillTree)
	router.GET("/api/incidents/:id/remediation", middleware.RequireAuth(), api.ListRemediationPlans)
	router.POST("/api/incidents/:id/remediation", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.CreateRemediationPlan)
	router.GET("/api/incidents/:id/remediation/:plan_id", middleware.RequireAuth(), api.GetRemediationPlan)
	router.POST("/api/incidents/:id/remediation/:plan_id/execute", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.ExecuteRemediationPlan)
	router.POST("/api/incidents/:id/remediation/:plan_id/steps/:step_id/execute", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.ExecuteRemediationStep)

	// ── ITDR — Identity Threat Detection & Response ──────────────────────────
	router.GET("/api/itdr/findings", middleware.RequireAuth(), api.ListITDRFindings)
	router.GET("/api/itdr/findings/:id", middleware.RequireAuth(), api.GetITDRFinding)
	router.PATCH("/api/itdr/findings/:id/status", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.UpdateITDRFindingStatus)
	router.GET("/api/itdr/summary", middleware.RequireAuth(), api.GetITDRSummary)

	// ── Alert Clustering ──────────────────────────────────────────────────────
	router.GET("/api/clusters", middleware.RequireAuth(), api.ListAlertClusters)
	router.GET("/api/clusters/:id/alerts", middleware.RequireAuth(), api.GetClusterAlerts)
	router.POST("/api/clusters/:id/suppress", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.SuppressCluster)
	router.POST("/api/clusters/analyze", middleware.RequireAuth(), api.TriggerClustering)

	// ── Framework Compliance ──────────────────────────────────────────────────
	router.GET("/api/framework-compliance", middleware.RequireAuth(), api.GetAllFrameworkAssessments)
	router.GET("/api/framework-compliance/:framework", middleware.RequireAuth(), api.GetFrameworkAssessment)

	// ── CIS Benchmark Compliance Scanning ────────────────────────────────────
	router.GET("/api/cis/summary", middleware.RequireAuth(), api.GetCISSummary)
	router.GET("/api/cis/agents/:id", middleware.RequireAuth(), api.GetAgentCISFindings)
	router.GET("/api/cis/agents/:id/score", middleware.RequireAuth(), api.GetAgentCISScore)
	router.POST("/api/cis/agents/:id/scan", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.TriggerCISScan)

	// ── JA3/TLS Fingerprint Blocklist ────────────────────────────────────────
	router.GET("/api/ja3/fingerprints", middleware.RequireAuth(), api.GetJA3Fingerprints)
	router.POST("/api/ja3/fingerprints", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.CreateJA3Fingerprint)
	router.DELETE("/api/ja3/fingerprints/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.DeleteJA3Fingerprint)

	// ── AD/LDAP Identity Cache ────────────────────────────────────────────────
	router.GET("/api/identity", middleware.RequireAuth(), api.GetIdentityCache)

	// ── Insider Threat Scores ─────────────────────────────────────────────────
	router.GET("/api/insider-threat", middleware.RequireAuth(), api.GetInsiderThreatScores)
	router.GET("/api/insider-threat/summary", middleware.RequireAuth(), api.GetInsiderThreatSummary)

	// ── Universal Log Ingest (syslog/CEF/LEEF/JSON via HTTP) ─────────────────
	// X-Api-Key authenticated — no user JWT needed. Accepts logs from any device
	// that can POST (firewalls, cloud pipelines, log shippers, etc.).
	router.POST("/api/ingest", api.RequireLogSourceAuth(), api.IngestLogs)

	// ── Log Sources management (user-facing CRUD) ─────────────────────────────
	router.GET("/api/log-sources", middleware.RequireAuth(), api.GetLogSources)
	router.POST("/api/log-sources", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.CreateLogSource)
	router.PUT("/api/log-sources/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.UpdateLogSource)
	router.DELETE("/api/log-sources/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.DeleteLogSource)

	// ── MDM — Mobile Device Management ───────────────────────────────────────
	// Devices (admin/dashboard)
	router.POST("/api/mdm/devices", middleware.RequireAuth(), api.EnrollMDMDevice)
	router.GET("/api/mdm/devices", middleware.RequireAuth(), api.ListMDMDevices)
	router.GET("/api/mdm/devices/:id", middleware.RequireAuth(), api.GetMDMDevice)
	router.DELETE("/api/mdm/devices/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.UnenrollMDMDevice)
	router.POST("/api/mdm/devices/:id/block", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.BlockMDMDevice)
	router.POST("/api/mdm/devices/:id/unblock", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.UnblockMDMDevice)
	// Compliance
	router.GET("/api/mdm/devices/:id/compliance", middleware.RequireAuth(), api.GetMDMDeviceCompliance)
	router.GET("/api/mdm/compliance/summary", middleware.RequireAuth(), api.GetMDMComplianceSummary)
	router.POST("/api/mdm/compliance/run", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.TriggerMDMCompliance)
	// Policies
	router.GET("/api/mdm/policies", middleware.RequireAuth(), api.ListMDMPolicies)
	router.POST("/api/mdm/policies", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.CreateMDMPolicy)
	// Commands
	router.POST("/api/mdm/devices/:id/commands", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.QueueMDMCommand)
	router.GET("/api/mdm/devices/:id/commands", middleware.RequireAuth(), api.ListMDMCommands)
	router.POST("/api/mdm/commands/:id/acknowledge", middleware.RequireAgentAuth(), api.AcknowledgeMDMCommand)
	// Profiles
	router.GET("/api/mdm/profiles", middleware.RequireAuth(), api.ListMDMProfiles)
	router.POST("/api/mdm/profiles", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.CreateMDMProfile)
	router.POST("/api/mdm/profiles/:id/deploy", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.DeployMDMProfile)

	// ── MDM Mobile — self-enrollment + agent-authenticated device ops ─────────
	// Enrollment token management (admin — RequireAuth)
	router.POST("/api/mdm/enrollment-tokens", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.CreateEnrollmentToken)
	router.GET("/api/mdm/enrollment-tokens", middleware.RequireAuth(), api.ListEnrollmentTokens)
	router.DELETE("/api/mdm/enrollment-tokens/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.RevokeEnrollmentToken)
	// Self-enroll — called by the mobile agent on first run (no user auth, only enrollment token)
	router.POST("/api/mdm/self-enroll", api.SelfEnrollDevice)
	// Agent-authenticated device operations (mobile agent uses agent_token)
	router.PUT("/api/mdm/devices/:id/checkin", middleware.RequireAgentAuth(), api.MobileDeviceCheckIn)
	router.GET("/api/mdm/devices/:id/commands/pending", middleware.RequireAgentAuth(), api.GetPendingMobileCommands)
	router.POST("/api/mdm/devices/:id/apps", middleware.RequireAgentAuth(), api.SubmitAppInventory)

	// ── Deep Packet Inspection / Advanced Detection ─────────────────
	router.GET("/api/dpi/findings", middleware.RequireAuth(), api.GetDPIFindings)
	router.GET("/api/dpi/summary", middleware.RequireAuth(), api.GetDPIFindingsSummary)

}
