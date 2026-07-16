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
	router.POST("/api/agents/bulk", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.BulkAgentAction)

	// ── Agents — :id wildcard routes ─────────────────────────────
	router.GET("/api/agents/:id", middleware.RequireAuth(), api.GetAgentByID)
	router.GET("/api/agents/:id/summary", middleware.RequireAuth(), api.GetAgentSummary)
	router.GET("/api/agents/:id/risk", middleware.RequireAuth(), api.GetRiskScore)
	router.GET("/api/timeline", middleware.RequireAuth(), api.GetTenantTimeline)
	router.GET("/api/timeline/stats", middleware.RequireAuth(), api.GetTimelineStats)
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
	// Static routes BEFORE :id wildcard
	router.GET("/api/incidents/analytics", middleware.RequireAuth(), api.GetIncidentAnalytics)
	// :id routes
	router.GET("/api/incidents/:id", middleware.RequireAuth(), api.GetIncidentByIDHandler)
	router.GET("/api/incidents/:id/events", middleware.RequireAuth(), api.GetIncidentEvents)
	router.GET("/api/incidents/:id/alerts", middleware.RequireAuth(), api.GetIncidentAlerts)
	router.PUT("/api/incidents/:id/status", middleware.RequireAuth(), api.UpdateIncidentStatus)
	router.PATCH("/api/incidents/:id/severity", middleware.RequireAuth(), api.UpdateIncidentSeverity)
	router.GET("/api/incidents/:id/tasks", middleware.RequireAuth(), api.GetIncidentTaskList)
	router.POST("/api/incidents/:id/tasks", middleware.RequireAuth(), api.CreateIncidentTask)
	router.PATCH("/api/incidents/:id/tasks/:tid", middleware.RequireAuth(), api.ToggleIncidentTask)
	router.POST("/api/incidents/:id/response-action", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.DispatchIncidentResponseAction)
	router.POST("/api/incidents/:id/ai-root-cause", middleware.RequireAuth(), api.AIIncidentRootCause)
	router.GET("/api/incidents/:id/similar", middleware.RequireAuth(), api.GetSimilarIncidents)

	// ── Quarantine ───────────────────────────────────────────────
	router.GET("/api/quarantine", middleware.RequireAuth(), api.GetQuarantinedFiles)

	// ── Sigma enterprise endpoints (static, must precede :id routes) ────
	router.GET("/api/sigma/dashboard",      middleware.RequireAuth(), api.GetSigmaDashboard)
	router.GET("/api/sigma/mitre-coverage", middleware.RequireAuth(), api.GetSigmaMITRECoverage)
	router.GET("/api/sigma/analytics",      middleware.RequireAuth(), api.GetSigmaAnalytics)
	router.GET("/api/sigma/categories",     middleware.RequireAuth(), api.GetSigmaCategories)
	router.GET("/api/sigma/performance",    middleware.RequireAuth(), api.GetSigmaPerformance)
	router.GET("/api/sigma/relationships",  middleware.RequireAuth(), api.GetSigmaRelationships)
	router.POST("/api/sigma/ai",            middleware.RequireAuth(), api.PostSigmaAI)
	router.POST("/api/sigma/convert",       middleware.RequireAuth(), api.PostSigmaConvert)
	router.POST("/api/sigma/bulk",          middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.PostSigmaBulk)
	router.POST("/api/sigma/export",        middleware.RequireAuth(), api.PostSigmaExport)
	router.GET("/api/sigma/rules/:id/detail", middleware.RequireAuth(), api.GetSigmaRuleDetail)

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

	// ── YARA enterprise (static routes before :id) ────────────────
	router.GET("/api/yara/dashboard",     middleware.RequireAuth(), api.GetYaraDashboard)
	router.GET("/api/yara/analytics",     middleware.RequireAuth(), api.GetYaraAnalytics)
	router.GET("/api/yara/categories",    middleware.RequireAuth(), api.GetYaraCategories)
	router.GET("/api/yara/performance",   middleware.RequireAuth(), api.GetYaraPerformance)
	router.GET("/api/yara/relationships", middleware.RequireAuth(), api.GetYaraRelationships)
	router.POST("/api/yara/ai",           middleware.RequireAuth(), api.PostYaraAI)
	router.POST("/api/yara/bulk",         middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.PostYaraBulk)
	router.POST("/api/yara/export",       middleware.RequireAuth(), api.PostYaraExport)
	router.GET("/api/yara/rules/:id/detail", middleware.RequireAuth(), api.GetYaraRuleDetail)

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
	router.GET("/api/platform/capabilities", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.GetPlatformCapabilities)
	router.POST("/api/platform/tenants", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.CreateTenantHandler)
	router.GET("/api/platform/tenants", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.GetTenantsHandler)
	router.PATCH("/api/platform/tenants/:id/toggle", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.ToggleTenantActiveHandler)
	router.DELETE("/api/platform/tenants/:id", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.DeleteTenantHandler)
	router.GET("/api/platform/tenants/:id/domains", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.GetTenantDomains)
	router.POST("/api/platform/tenants/:id/domains", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.AddTenantDomain)
	router.DELETE("/api/platform/tenants/:id/domains/:did", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.DeleteTenantDomain)
	router.POST("/api/platform/agent-releases", middleware.RequireAuthOrCIToken(), middleware.RequirePlatformAdmin(), api.PublishAgentRelease)
	router.GET("/api/platform/agent-releases", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.GetAgentReleases)
	router.GET("/api/agent-releases/:platform", middleware.RequireAgentAuth(), api.GetLatestAgentRelease)

	// ── License (public check + admin management) ───────────────────
	router.POST("/api/license/check", api.CheckLicenseHandler)
	router.GET("/api/platform/license/mode", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.GetLicenseModeHandler)
	router.POST("/api/platform/license/mode", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.SetLicenseModeHandler)
	router.GET("/api/platform/license/keys", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.ListLicenseKeysHandler)
	router.POST("/api/platform/license/keys", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.GenerateLicenseKeyHandler)
	router.DELETE("/api/platform/license/keys/:keyID", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.RevokeLicenseKeyHandler)
	router.POST("/api/platform/license/keys/:keyID/regenerate", middleware.RequireAuth(), middleware.RequirePlatformAdmin(), api.RegenerateLicenseTokenHandler)

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

	// ── Live log statistics + AI log explain ─────────────────────────────────
	router.GET("/api/live-logs/stats", middleware.RequireAuth(), api.GetLiveLogStats)
	router.POST("/api/ai/explain-log", middleware.RequireAuth(), api.ExplainLogEntry)
	router.POST("/api/ai/summarize-logs", middleware.RequireAuth(), api.SummarizeLogs)

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
	// enterprise log search extensions
	router.GET("/api/logs/fields", middleware.RequireAuth(), api.GetLogFields)
	router.GET("/api/logs/templates", middleware.RequireAuth(), api.GetSearchTemplates)
	router.POST("/api/logs/ai-query", middleware.RequireAuth(), api.AIQuery)
	router.POST("/api/logs/ai-explain", middleware.RequireAuth(), api.AIExplainResults)
	router.POST("/api/logs/build-detection", middleware.RequireAuth(), api.BuildDetection)
	router.GET("/api/logs/scheduled", middleware.RequireAuth(), api.GetScheduledSearches)
	router.POST("/api/logs/scheduled", middleware.RequireAuth(), api.CreateScheduledSearch)
	router.DELETE("/api/logs/scheduled/:id", middleware.RequireAuth(), api.DeleteScheduledSearch)

	// ── Elasticsearch raw query interface ─────────────────────────
	router.POST("/api/elastic/query", middleware.RequireAuth(), middleware.RateLimitAPI(), api.ElasticQueryHandler)
	router.POST("/api/elastic/explain", middleware.RequireAuth(), api.ElasticExplainHandler)
	router.GET("/api/elastic/indices", middleware.RequireAuth(), api.ElasticIndicesHandler)
	router.GET("/api/elastic/mappings/:index", middleware.RequireAuth(), api.ElasticMappingsHandler)
	router.GET("/api/elastic/health", middleware.RequireAuth(), api.ElasticHealthHandler)
	router.POST("/api/ai/es-query", middleware.RequireAuth(), api.ElasticAIQueryHandler)

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
	// Enterprise correlation — static routes BEFORE :id wildcards
	router.GET("/api/correlation/overview",      middleware.RequireAuth(), api.GetCorrelationOverview)
	router.GET("/api/correlation/trends",         middleware.RequireAuth(), api.GetCorrelationTrends)
	router.GET("/api/correlation/analytics",      middleware.RequireAuth(), api.GetCorrelationAnalytics)
	router.GET("/api/correlation/graph",          middleware.RequireAuth(), api.GetCorrelationGraph)
	router.GET("/api/correlation/alert-grouping", middleware.RequireAuth(), api.GetCorrelationAlertGrouping)
	router.GET("/api/correlation/performance",    middleware.RequireAuth(), api.GetCorrelationPerformance)
	router.POST("/api/correlation/ai-analysis",   middleware.RequireAuth(), api.PostCorrelationAI)
	router.POST("/api/correlation/simulate",      middleware.RequireAuth(), api.PostCorrelationSimulate)
	// Core rule CRUD
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
	// ── Agent inventory (lazy-loaded detail tabs) ─────────────────
	router.GET("/api/agents/:id/startup", middleware.RequireAuth(), api.GetAgentStartupItems)
	router.GET("/api/agents/:id/usb-history", middleware.RequireAuth(), api.GetAgentUsbHistory)
	router.GET("/api/agents/:id/login-history", middleware.RequireAuth(), api.GetAgentLoginHistory)
	router.GET("/api/agents/:id/scheduled-tasks", middleware.RequireAuth(), api.GetAgentScheduledTasksList)
	router.GET("/api/agents/:id/drivers", middleware.RequireAuth(), api.GetAgentDriversList)
	router.GET("/api/agents/:id/policies", middleware.RequireAuth(), api.GetAgentPolicies)
	router.GET("/api/agents/:id/audit-history", middleware.RequireAuth(), api.GetAgentAuditHistory)

	// ── Agent Groups ──────────────────────────────────────────────
	router.GET("/api/agent-groups", middleware.RequireAuth(), api.ListAgentGroups)
	router.POST("/api/agent-groups", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.CreateAgentGroup)
	router.DELETE("/api/agent-groups/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.DeleteAgentGroup)

	router.GET("/api/agents/me", middleware.RequireAgentAuth(), api.GetCurrentAgent)
	router.GET("/api/agents/self/summary",  middleware.RequireAgentAuth(), api.GetSelfSummary)
	router.GET("/api/agents/self/alerts",   middleware.RequireAgentAuth(), api.GetSelfAlerts)
	router.GET("/api/agents/self/timeline", middleware.RequireAgentAuth(), api.GetSelfTimeline)
	router.GET("/api/agents/self/tasks",    middleware.RequireAgentAuth(), api.GetSelfTasks)
	router.GET("/api/agents/:id/geo-stats", middleware.RequireAuth(), api.GetAgentGeoStats)
	router.POST("/api/agents/:id/enrich-connections", middleware.RequireAuth(), api.EnrichAgentConnections)
	router.GET("/api/agents/:id/health", middleware.RequireAuth(), api.GetAgentHealth)
	router.GET("/api/agents/:id/security-status", middleware.RequireAuth(), api.GetAgentSecurityStatus)
	router.GET("/api/geoip/:ip", middleware.RequireAuth(), api.GetGeoIP)
	router.GET("/api/ioc-blocks", middleware.RequireAuth(), api.GetIOCBlocks)
	router.GET("/api/quarantine/stats", middleware.RequireAuth(), api.GetQuarantineStats)
	router.DELETE("/api/quarantine/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_quarantine"), api.ReleaseQuarantinedFile)
	router.POST("/api/quarantine", middleware.RequireAuth(), middleware.RequirePermission("manage_quarantine"), api.ReceiveQuarantinedFile)
	router.GET("/api/notifications/email", middleware.RequireAuth(), api.GetEmailRules)
	router.POST("/api/notifications/email", middleware.RequireAuth(), middleware.RequirePermission("manage_notifications"), api.CreateEmailRule)
	router.PATCH("/api/notifications/email/:id/toggle", middleware.RequireAuth(), middleware.RequirePermission("manage_notifications"), api.ToggleEmailRule)
	router.DELETE("/api/notifications/email/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_notifications"), api.DeleteEmailRule)
	router.GET("/api/settings/smtp", middleware.RequireAuth(), api.GetTenantSMTPConfig)
	router.PUT("/api/settings/smtp", middleware.RequireAuth(), middleware.RequirePermission("manage_notifications"), api.SaveTenantSMTPConfig)
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
	// Static routes BEFORE parameterized :username routes
	router.GET("/api/ueba/analytics", middleware.RequireAuth(), api.GetUEBAAnalytics)
	router.GET("/api/ueba/watchlist", middleware.RequireAuth(), api.GetUEBAWatchlist)
	router.POST("/api/ueba/watchlist", middleware.RequireAuth(), api.AddToUEBAWatchlist)
	router.DELETE("/api/ueba/watchlist/:username", middleware.RequireAuth(), api.RemoveFromUEBAWatchlist)
	// List + analyze
	router.GET("/api/ueba/users", middleware.RequireAuth(), api.GetUEBAUsers)
	router.GET("/api/ueba/events", middleware.RequireAuth(), api.GetUEBAEvents)
	router.POST("/api/ueba/analyze", middleware.RequireAuth(), middleware.RequirePermission("run_ai_analysis"), api.TriggerUEBAAnalysis)
	// Per-user detail routes
	router.GET("/api/ueba/users/:username", middleware.RequireAuth(), api.GetUEBAUserDetail)
	router.GET("/api/ueba/users/:username/timeline", middleware.RequireAuth(), api.GetUEBAUserTimeline)
	router.GET("/api/ueba/users/:username/peer-comparison", middleware.RequireAuth(), api.GetUEBAPeerComparison)
	router.POST("/api/ueba/users/:username/ai-insights", middleware.RequireAuth(), api.GetUEBAUserAIInsights)
	router.POST("/api/ueba/users/:username/response-action", middleware.RequireAuth(), middleware.RequirePermission("manage_users"), api.UEBAResponseAction)

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

	// ── Threat Hunt Enterprise ───────────────────────────────────────────
	// Static routes registered first to prevent Gin radix conflict with /:id
	router.GET("/api/threat-hunt/dashboard",          middleware.RequireAuth(), api.GetThreatHuntDashboard)
	router.GET("/api/threat-hunt/library",            middleware.RequireAuth(), api.GetThreatHuntLibrary)
	router.GET("/api/threat-hunt/categories",         middleware.RequireAuth(), api.GetThreatHuntCategories)
	router.GET("/api/threat-hunt/findings",           middleware.RequireAuth(), api.GetThreatHuntFindings)
	router.GET("/api/threat-hunt/metrics",            middleware.RequireAuth(), api.GetThreatHuntMetrics)
	router.POST("/api/threat-hunt",                   middleware.RequireAuth(), api.PostThreatHunt)
	router.POST("/api/threat-hunt/ai",                middleware.RequireAuth(), api.PostThreatHuntAI)
	router.POST("/api/threat-hunt/export",            middleware.RequireAuth(), api.PostThreatHuntExport)
	router.POST("/api/threat-hunt/response",          middleware.RequireAuth(), api.PostThreatHuntResponse)
	router.POST("/api/threat-hunt/findings/:fid/ack", middleware.RequireAuth(), api.PostThreatHuntFindingAck)
	router.GET("/api/threat-hunt/:id",                middleware.RequireAuth(), api.GetThreatHunt)
	router.PATCH("/api/threat-hunt/:id",              middleware.RequireAuth(), api.PatchThreatHunt)
	router.DELETE("/api/threat-hunt/:id",             middleware.RequireAuth(), api.DeleteThreatHunt)
	router.POST("/api/threat-hunt/:id/execute",       middleware.RequireAuth(), api.PostThreatHuntExecute)
	router.POST("/api/threat-hunt/:id/schedule",      middleware.RequireAuth(), api.PostThreatHuntSchedule)
	router.POST("/api/threat-hunt/:id/comment",       middleware.RequireAuth(), api.PostThreatHuntComment)
	router.GET("/api/threat-hunt/:id/comments",       middleware.RequireAuth(), api.GetThreatHuntComments)

	// ── Hunt Workbench Enterprise ────────────────────────────────────────
	router.GET("/api/hunt/dashboard",        middleware.RequireAuth(), api.GetHuntDashboard)
	router.GET("/api/hunt/analytics",        middleware.RequireAuth(), api.GetHuntAnalytics)
	router.GET("/api/hunt/mitre-coverage",   middleware.RequireAuth(), api.GetHuntMITRECoverage)
	router.POST("/api/hunt/ai",              middleware.RequireAuth(), api.PostHuntAI)
	router.POST("/api/hunt/ioc",             middleware.RequireAuth(), api.PostHuntIOC)
	router.POST("/api/hunt/ttp",             middleware.RequireAuth(), api.PostHuntTTP)
	router.POST("/api/hunt/actor",           middleware.RequireAuth(), api.PostHuntActor)
	router.POST("/api/hunt/export",          middleware.RequireAuth(), api.PostHuntExport)
	router.GET("/api/hunt/notebook",         middleware.RequireAuth(), api.GetHuntNotebook)
	router.POST("/api/hunt/notebook",        middleware.RequireAuth(), api.PostHuntNotebook)
	router.DELETE("/api/hunt/notebook/:nid", middleware.RequireAuth(), api.DeleteHuntNotebook)
	router.POST("/api/hunt/response",        middleware.RequireAuth(), api.PostHuntResponse)

	// ── Hunt Workbench ────────────────────────────────────────────────────
	router.GET("/api/hunt/templates", middleware.RequireAuth(), api.ListHuntTemplates)
	router.POST("/api/hunt/templates", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.CreateHuntTemplate)
	router.DELETE("/api/hunt/templates/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.DeleteHuntTemplate)
	router.GET("/api/hunt/runs", middleware.RequireAuth(), api.ListHuntRuns)
	router.GET("/api/hunt/runs/:id", middleware.RequireAuth(), api.GetHuntRunDetail)
	router.POST("/api/hunt/execute", middleware.RequireAuth(), api.ExecuteHunt)
	router.PATCH("/api/hunt/runs/:id/notes", middleware.RequireAuth(), api.UpdateHuntRunNotes)

	// ── Threat Intelligence Enterprise ───────────────────────────────────────
	router.GET("/api/intel/overview",      middleware.RequireAuth(), api.GetIntelOverview)
	router.GET("/api/intel/analytics",     middleware.RequireAuth(), api.GetIntelAnalytics)
	router.GET("/api/intel/campaigns",     middleware.RequireAuth(), api.GetIntelCampaigns)
	router.GET("/api/intel/mitre",         middleware.RequireAuth(), api.GetIntelMITRECoverage)
	router.GET("/api/intel/relationships", middleware.RequireAuth(), api.GetIntelRelationships)
	router.GET("/api/intel/watchlist",     middleware.RequireAuth(), api.GetIntelWatchlist)
	router.GET("/api/intel/timeline",      middleware.RequireAuth(), api.GetIntelIOCTimeline)
	router.POST("/api/intel/search",       middleware.RequireAuth(), api.PostIntelSearch)
	router.POST("/api/intel/ai",           middleware.RequireAuth(), api.PostIntelAI)

	// ── Threat Actor Intelligence — static routes BEFORE :id wildcards ──────
	router.GET("/api/threat-actors/dashboard",  middleware.RequireAuth(), api.GetActorDashboard)
	router.GET("/api/threat-actors/analytics",  middleware.RequireAuth(), api.GetActorAnalytics)
	router.POST("/api/threat-actors/ai",        middleware.RequireAuth(), api.PostActorAI)
	router.GET("/api/threat-actors",            middleware.RequireAuth(), api.ListThreatActors)
	router.POST("/api/threat-actors",           middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.CreateThreatActor)
	router.DELETE("/api/threat-actors/:id",     middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.DeleteThreatActor)
	router.PATCH("/api/threat-actors/:id",      middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.UpdateThreatActor)
	router.GET("/api/threat-actors/:id/alerts",             middleware.RequireAuth(), api.GetActorAlerts)
	router.GET("/api/threat-actors/:id/profile",            middleware.RequireAuth(), api.GetActorDetail)
	router.GET("/api/threat-actors/:id/campaigns",          middleware.RequireAuth(), api.GetActorCampaigns)
	router.GET("/api/threat-actors/:id/malware",            middleware.RequireAuth(), api.GetActorMalware)
	router.GET("/api/threat-actors/:id/infrastructure",     middleware.RequireAuth(), api.GetActorInfrastructure)
	router.GET("/api/threat-actors/:id/exposure",           middleware.RequireAuth(), api.GetActorExposure)
	router.GET("/api/threat-actors/:id/detection-coverage", middleware.RequireAuth(), api.GetActorDetectionCoverage)
	router.GET("/api/threat-actors/:id/relationships",      middleware.RequireAuth(), api.GetActorRelationships)
	router.GET("/api/threat-actors/:id/timeline",           middleware.RequireAuth(), api.GetActorTimeline)
	router.GET("/api/threat-actors/:id/iocs",               middleware.RequireAuth(), api.GetActorIOCs)
	router.GET("/api/threat-actors/:id/mitre",              middleware.RequireAuth(), api.GetActorMITRE)
	router.POST("/api/threat-actors/:id/hunt",              middleware.RequireAuth(), api.PostActorHunt)
	router.POST("/api/threat-actors/:id/response",          middleware.RequireAuth(), api.PostActorResponse)
	router.GET("/api/alerts/:id/actor-tags",                middleware.RequireAuth(), api.GetAlertActorTags)

	// ── Playbook Recommender ──────────────────────────────────────────────────
	router.GET("/api/alerts/:id/playbook-recommendations", middleware.RequireAuth(), api.GetPlaybookRecommendations)
	router.POST("/api/alerts/:id/execute-recommendation", middleware.RequireAuth(), api.ExecuteRecommendedPlaybook)

	// ── Network Behavior Analytics ────────────────────────────────────────────
	router.GET("/api/nba/overview", middleware.RequireAuth(), api.GetNBAOverview)
	router.GET("/api/nba/flows", middleware.RequireAuth(), api.GetNBAFlows)
	router.GET("/api/nba/traffic-analysis", middleware.RequireAuth(), api.GetNBATrafficAnalysis)
	router.GET("/api/nba/dns-analytics", middleware.RequireAuth(), api.GetNBADNSAnalytics)
	router.GET("/api/nba/tls-analytics", middleware.RequireAuth(), api.GetNBATLSAnalytics)
	router.GET("/api/nba/beacons", middleware.RequireAuth(), api.GetNBABeacons)
	router.GET("/api/nba/lateral-movement", middleware.RequireAuth(), api.GetNBALateralMovement)
	router.GET("/api/nba/threat-intel", middleware.RequireAuth(), api.GetNBAThreatIntel)
	router.POST("/api/nba/ai-insights", middleware.RequireAuth(), api.PostNBAAIInsights)
	router.POST("/api/nba/response-action", middleware.RequireAuth(), api.PostNBAResponseAction)
	router.GET("/api/nba/mitre-mapping", middleware.RequireAuth(), api.GetNBAMitreMapping)
	router.GET("/api/nba/protocol-breakdown", middleware.RequireAuth(), api.GetNBAProtocolBreakdown)
	router.GET("/api/nba/host-timeline", middleware.RequireAuth(), api.GetNBAHostTimeline)
	router.GET("/api/nba/analytics", middleware.RequireAuth(), api.GetNBAAnalytics)
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

	// ── Alert Clustering — enterprise static routes BEFORE :id wildcards ──────
	router.GET("/api/clusters/overview",   middleware.RequireAuth(), api.GetClusterOverview)
	router.GET("/api/clusters/list",       middleware.RequireAuth(), api.GetClusterList)
	router.GET("/api/clusters/analytics",  middleware.RequireAuth(), api.GetClusterAnalytics)
	router.GET("/api/clusters/campaigns",  middleware.RequireAuth(), api.GetClusterCampaigns)
	router.POST("/api/clusters/ai",        middleware.RequireAuth(), api.PostClusterAI)
	router.POST("/api/clusters/analyze",   middleware.RequireAuth(), api.TriggerClustering)
	// Core cluster endpoints
	router.GET("/api/clusters",                 middleware.RequireAuth(), api.ListAlertClusters)
	router.GET("/api/clusters/:id/alerts",      middleware.RequireAuth(), api.GetClusterAlerts)
	router.GET("/api/clusters/:id/detail",      middleware.RequireAuth(), api.GetClusterDetail)
	router.GET("/api/clusters/:id/timeline",    middleware.RequireAuth(), api.GetClusterTimeline)
	router.GET("/api/clusters/:id/graph",       middleware.RequireAuth(), api.GetClusterGraph)
	router.POST("/api/clusters/:id/suppress",   middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.SuppressCluster)
	router.POST("/api/clusters/:id/bulk-action", middleware.RequireAuth(), api.PostClusterBulkAction)
	router.POST("/api/clusters/:id/merge",      middleware.RequireAuth(), api.PostClusterMerge)

	// ── Framework Compliance ──────────────────────────────────────────────────
	router.GET("/api/framework-compliance", middleware.RequireAuth(), api.GetAllFrameworkAssessments)
	router.GET("/api/framework-compliance/:framework", middleware.RequireAuth(), api.GetFrameworkAssessment)

	// ── CIS Benchmark Compliance Scanning ────────────────────────────────────
	router.GET("/api/cis/summary", middleware.RequireAuth(), api.GetCISSummary)
	router.GET("/api/cis/agents/:id", middleware.RequireAuth(), api.GetAgentCISFindings)
	router.GET("/api/cis/agents/:id/score", middleware.RequireAuth(), api.GetAgentCISScore)
	router.POST("/api/cis/agents/:id/scan", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.TriggerCISScan)

	// ── JA3 Enterprise ────────────────────────────────────────────────────────
	router.GET("/api/ja3/dashboard",                   middleware.RequireAuth(), api.GetJA3Dashboard)
	router.GET("/api/ja3/analytics",                   middleware.RequireAuth(), api.GetJA3Analytics)
	router.GET("/api/ja3/tls-stats",                   middleware.RequireAuth(), api.GetJA3TLSStats)
	router.GET("/api/ja3/behavioral",                  middleware.RequireAuth(), api.GetJA3Behavioral)
	router.GET("/api/ja3/relationships",               middleware.RequireAuth(), api.GetJA3Relationships)
	router.GET("/api/ja3/threat-intel",                middleware.RequireAuth(), api.GetJA3ThreatIntel)
	router.GET("/api/ja3/timeline",                    middleware.RequireAuth(), api.GetJA3Timeline)
	router.GET("/api/ja3/watchlist",                   middleware.RequireAuth(), api.GetJA3Watchlist)
	router.POST("/api/ja3/watchlist",                  middleware.RequireAuth(), api.PostJA3Watchlist)
	router.DELETE("/api/ja3/watchlist/:id",            middleware.RequireAuth(), api.DeleteJA3WatchlistItem)
	router.POST("/api/ja3/ai",                         middleware.RequireAuth(), api.PostJA3AI)
	router.POST("/api/ja3/export",                     middleware.RequireAuth(), api.PostJA3Export)
	router.POST("/api/ja3/bulk",                       middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.PostJA3Bulk)
	router.GET("/api/ja3/fingerprints/:hash/detail",   middleware.RequireAuth(), api.GetJA3FingerprintDetail)

	// ── JA3/TLS Fingerprint Blocklist ────────────────────────────────────────
	router.GET("/api/ja3/fingerprints", middleware.RequireAuth(), api.GetJA3Fingerprints)
	router.POST("/api/ja3/fingerprints", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.CreateJA3Fingerprint)
	router.DELETE("/api/ja3/fingerprints/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_detection_rules"), api.DeleteJA3Fingerprint)

	// ── AD/LDAP Identity Cache ────────────────────────────────────────────────
	router.GET("/api/identity", middleware.RequireAuth(), api.GetIdentityCache)

	// ── Insider Threat Scores ─────────────────────────────────────────────────
	router.GET("/api/insider-threat", middleware.RequireAuth(), api.GetInsiderThreatScores)
	router.GET("/api/insider-threat/summary", middleware.RequireAuth(), api.GetInsiderThreatSummary)
	// Enterprise — static routes BEFORE :username wildcard
	router.GET("/api/insider-threat/analytics", middleware.RequireAuth(), api.GetInsiderThreatAnalytics)
	router.GET("/api/insider-threat/policy-violations", middleware.RequireAuth(), api.GetInsiderPolicyViolations)
	router.GET("/api/insider-threat/policies", middleware.RequireAuth(), api.GetInsiderPolicies)
	router.POST("/api/insider-threat/policies", middleware.RequireAuth(), middleware.RequirePermission("manage_incidents"), api.CreateInsiderPolicy)
	router.GET("/api/insider-threat/watchlist", middleware.RequireAuth(), api.GetInsiderWatchlist)
	router.POST("/api/insider-threat/watchlist", middleware.RequireAuth(), api.AddToInsiderWatchlist)
	router.DELETE("/api/insider-threat/watchlist/:username", middleware.RequireAuth(), api.RemoveFromInsiderWatchlist)
	// Per-user routes
	router.GET("/api/insider-threat/users/:username", middleware.RequireAuth(), api.GetInsiderThreatUserDetail)
	router.GET("/api/insider-threat/users/:username/timeline", middleware.RequireAuth(), api.GetInsiderThreatUserTimeline)
	router.POST("/api/insider-threat/users/:username/ai-analysis", middleware.RequireAuth(), api.GetInsiderThreatAIAnalysis)
	router.POST("/api/insider-threat/users/:username/response-action", middleware.RequireAuth(), middleware.RequirePermission("manage_users"), api.InsiderThreatResponseAction)

	// ── Universal Log Ingest (syslog/CEF/LEEF/JSON via HTTP) ─────────────────
	// X-Api-Key authenticated — no user JWT needed. Accepts logs from any device
	// that can POST (firewalls, cloud pipelines, log shippers, etc.).
	router.POST("/api/ingest", api.RequireLogSourceAuth(), api.IngestLogs)

	// ── Log Sources management (user-facing CRUD) ─────────────────────────────
	router.GET("/api/log-sources", middleware.RequireAuth(), api.GetLogSources)
	router.POST("/api/log-sources", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.CreateLogSource)
	router.PUT("/api/log-sources/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.UpdateLogSource)
	router.DELETE("/api/log-sources/:id", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.DeleteLogSource)
	// Static sub-routes must be registered before :id routes
	router.GET("/api/log-sources/monitoring", middleware.RequireAuth(), api.GetLogSourceMonitoring)
	router.GET("/api/log-sources/marketplace", middleware.RequireAuth(), api.GetLogSourceMarketplace)
	router.POST("/api/log-sources/ai-insights", middleware.RequireAuth(), api.AILogSourceInsights)
	router.POST("/api/log-sources/bulk", middleware.RequireAuth(), middleware.RequirePermission("manage_agents"), api.BulkUpdateLogSources)
	// Per-source detail routes
	router.GET("/api/log-sources/:id/health", middleware.RequireAuth(), api.GetLogSourceHealth)
	router.GET("/api/log-sources/:id/stats", middleware.RequireAuth(), api.GetLogSourceStats)
	router.GET("/api/log-sources/:id/parser", middleware.RequireAuth(), api.GetLogSourceParser)
	router.GET("/api/log-sources/:id/recent-logs", middleware.RequireAuth(), api.GetLogSourceRecentLogs)
	router.POST("/api/log-sources/:id/test", middleware.RequireAuth(), api.TestLogSourceConnection)

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

	// ── Detection Engineering Dashboard ─────────────────────────────────────
	router.GET("/api/detection/overview",      middleware.RequireAuth(), api.GetDetectionOverview)
	router.GET("/api/detection/trends",        middleware.RequireAuth(), api.GetDetectionTrends)
	router.GET("/api/detection/coverage",      middleware.RequireAuth(), api.GetDetectionCoverage)
	router.GET("/api/detection/analytics",     middleware.RequireAuth(), api.GetDetectionAnalytics)
	router.GET("/api/detection/performance",   middleware.RequireAuth(), api.GetDetectionPerformance)
	router.POST("/api/detection/ai-assistant", middleware.RequireAuth(), api.PostDetectionAIAssistant)
	router.POST("/api/detection/simulate",     middleware.RequireAuth(), api.PostDetectionSimulate)

	// ── Deep Packet Inspection / Advanced Detection ─────────────────
	router.GET("/api/dpi/overview",          middleware.RequireAuth(), api.GetDPIOverview)
	router.GET("/api/dpi/sessions",          middleware.RequireAuth(), api.GetDPISessions)
	router.GET("/api/dpi/http-inspection",   middleware.RequireAuth(), api.GetDPIHTTPInspection)
	router.GET("/api/dpi/dns-inspection",    middleware.RequireAuth(), api.GetDPIDNSInspection)
	router.GET("/api/dpi/tls-inspection",    middleware.RequireAuth(), api.GetDPITLSInspection)
	router.GET("/api/dpi/files",             middleware.RequireAuth(), api.GetDPIFiles)
	router.GET("/api/dpi/dlp",               middleware.RequireAuth(), api.GetDPIDLP)
	router.GET("/api/dpi/analytics",         middleware.RequireAuth(), api.GetDPIAnalytics)
	router.GET("/api/dpi/performance",       middleware.RequireAuth(), api.GetDPIPerformance)
	router.GET("/api/dpi/protocol-anomalies",middleware.RequireAuth(), api.GetDPIProtocolAnomalies)
	router.GET("/api/dpi/search",            middleware.RequireAuth(), api.GetDPISearch)
	router.POST("/api/dpi/ai-inspect",       middleware.RequireAuth(), api.PostDPIAIInspect)
	router.POST("/api/dpi/response-action",  middleware.RequireAuth(), api.PostDPIResponseAction)
	router.GET("/api/dpi/findings",          middleware.RequireAuth(), api.GetDPIFindings)
	router.GET("/api/dpi/summary",           middleware.RequireAuth(), api.GetDPIFindingsSummary)

	// ── DFIR Enterprise ───────────────────────────────────────────────────────
	// Static routes registered before /:id to prevent Gin radix conflict
	router.GET("/api/dfir/dashboard",                   middleware.RequireAuth(), api.GetDFIRDashboard)
	router.GET("/api/dfir/investigations",              middleware.RequireAuth(), api.GetDFIRInvestigations)
	router.POST("/api/dfir/investigations",             middleware.RequireAuth(), api.PostDFIRInvestigation)
	router.GET("/api/dfir/evidence",                    middleware.RequireAuth(), api.GetDFIREvidence)
	router.POST("/api/dfir/file-analysis",              middleware.RequireAuth(), api.PostDFIRFileAnalysis)
	router.POST("/api/dfir/malware-analysis",           middleware.RequireAuth(), api.PostDFIRMalwareAnalysis)
	router.GET("/api/dfir/search",                      middleware.RequireAuth(), api.GetDFIRSearch)
	router.GET("/api/dfir/analytics",                   middleware.RequireAuth(), api.GetDFIRAnalytics)
	// Investigation-scoped
	router.GET("/api/dfir/investigations/:id",              middleware.RequireAuth(), api.GetDFIRInvestigation)
	router.PATCH("/api/dfir/investigations/:id",            middleware.RequireAuth(), api.PatchDFIRInvestigation)
	router.DELETE("/api/dfir/investigations/:id",           middleware.RequireAuth(), api.DeleteDFIRInvestigation)
	router.POST("/api/dfir/investigations/:id/collect",     middleware.RequireAuth(), api.PostDFIRCollect)
	router.GET("/api/dfir/investigations/:id/tasks",        middleware.RequireAuth(), api.GetDFIRCollectionTasks)
	router.POST("/api/dfir/investigations/:id/ai",          middleware.RequireAuth(), api.PostDFIRAI)
	router.POST("/api/dfir/investigations/:id/report",      middleware.RequireAuth(), api.PostDFIRReport)
	router.POST("/api/dfir/investigations/:id/response",    middleware.RequireAuth(), api.PostDFIRResponse)
	router.GET("/api/dfir/investigations/:id/timeline",     middleware.RequireAuth(), api.GetDFIRTimeline)
	router.POST("/api/dfir/investigations/:id/timeline",    middleware.RequireAuth(), api.PostDFIRTimelineEvent)
	router.GET("/api/dfir/investigations/:id/process-tree", middleware.RequireAuth(), api.GetDFIRProcessTree)
	router.POST("/api/dfir/investigations/:id/memory",      middleware.RequireAuth(), api.PostDFIRMemoryAnalyze)
	router.GET("/api/dfir/investigations/:id/network",      middleware.RequireAuth(), api.GetDFIRNetworkForensics)
	router.GET("/api/dfir/investigations/:id/artifacts",    middleware.RequireAuth(), api.GetDFIRArtifacts)
	router.GET("/api/dfir/investigations/:id/evidence",     middleware.RequireAuth(), api.GetDFIREvidence)
	router.GET("/api/dfir/investigations/:id/notebook",     middleware.RequireAuth(), api.GetDFIRNotebook)
	router.POST("/api/dfir/investigations/:id/notebook",    middleware.RequireAuth(), api.PostDFIRNotebook)
	router.GET("/api/dfir/investigations/:id/graph",        middleware.RequireAuth(), api.GetDFIRRelationshipGraph)
	router.GET("/api/dfir/investigations/:id/threat-intel", middleware.RequireAuth(), api.GetDFIRThreatIntel)
	// Evidence-scoped
	router.GET("/api/dfir/evidence/:eid",                   middleware.RequireAuth(), api.GetDFIREvidenceItem)
	router.GET("/api/dfir/evidence/:eid/custody",           middleware.RequireAuth(), api.GetDFIRCustody)
	router.POST("/api/dfir/evidence/:eid/custody",          middleware.RequireAuth(), api.PostDFIRCustody)
	// Notebook entry deletion
	router.DELETE("/api/dfir/notebook/:nid",                middleware.RequireAuth(), api.DeleteDFIRNotebookEntry)

	// ── OT/ICS Security Enterprise ───────────────────────────────────────────
	router.GET("/api/ot/dashboard",     middleware.RequireAuth(), api.GetOTDashboard)
	router.GET("/api/ot/assets",        middleware.RequireAuth(), api.GetOTAssets)
	router.GET("/api/ot/topology",      middleware.RequireAuth(), api.GetOTTopology)
	router.GET("/api/ot/protocols",     middleware.RequireAuth(), api.GetOTProtocols)
	router.GET("/api/ot/traffic",       middleware.RequireAuth(), api.GetOTTraffic)
	router.GET("/api/ot/alerts",        middleware.RequireAuth(), api.GetOTAlerts)
	router.GET("/api/ot/devices",       middleware.RequireAuth(), api.GetOTDeviceStatus)
	router.GET("/api/ot/threats",       middleware.RequireAuth(), api.GetOTThreatDetection)
	router.GET("/api/ot/dpi",           middleware.RequireAuth(), api.GetOTDPI)
	router.GET("/api/ot/risk",          middleware.RequireAuth(), api.GetOTRiskAssessment)
	router.GET("/api/ot/vulnerabilities",middleware.RequireAuth(), api.GetOTVulnerabilities)
	router.GET("/api/ot/zones",         middleware.RequireAuth(), api.GetOTZones)
	router.GET("/api/ot/baseline",      middleware.RequireAuth(), api.GetOTBaseline)
	router.GET("/api/ot/threat-intel",  middleware.RequireAuth(), api.GetOTThreatIntel)
	router.GET("/api/ot/timeline",      middleware.RequireAuth(), api.GetOTTimeline)
	router.GET("/api/ot/compliance",    middleware.RequireAuth(), api.GetOTCompliance)
	router.GET("/api/ot/attack-paths",  middleware.RequireAuth(), api.GetOTAttackPaths)
	router.GET("/api/ot/analytics",     middleware.RequireAuth(), api.GetOTAnalytics)
	router.POST("/api/ot/ai",           middleware.RequireAuth(), api.PostOTAI)
	router.POST("/api/ot/response",     middleware.RequireAuth(), api.PostOTResponse)
	router.POST("/api/ot/report",       middleware.RequireAuth(), api.PostOTReport)

	// ── Supply Chain Security Enterprise ────────────────────────────────────
	router.GET("/api/supply-chain/dashboard",      middleware.RequireAuth(), api.GetSCDashboard)
	router.GET("/api/supply-chain/repositories",   middleware.RequireAuth(), api.GetSCRepositories)
	router.GET("/api/supply-chain/dependencies",   middleware.RequireAuth(), api.GetSCDependencies)
	router.GET("/api/supply-chain/vulnerabilities",middleware.RequireAuth(), api.GetSCVulnerabilities)
	router.GET("/api/supply-chain/sboms",          middleware.RequireAuth(), api.GetSCSBOMs)
	router.GET("/api/supply-chain/pipelines",      middleware.RequireAuth(), api.GetSCBuildPipelines)
	router.GET("/api/supply-chain/secrets",        middleware.RequireAuth(), api.GetSCSecretFindings)
	router.GET("/api/supply-chain/code-integrity", middleware.RequireAuth(), api.GetSCCodeIntegrity)
	router.GET("/api/supply-chain/artifacts",      middleware.RequireAuth(), api.GetSCArtifacts)
	router.GET("/api/supply-chain/third-party",    middleware.RequireAuth(), api.GetSCThirdPartyRisk)
	router.GET("/api/supply-chain/provenance",     middleware.RequireAuth(), api.GetSCBuildProvenance)
	router.GET("/api/supply-chain/threat-intel",   middleware.RequireAuth(), api.GetSCThreatIntel)
	router.GET("/api/supply-chain/timeline",       middleware.RequireAuth(), api.GetSCTimeline)
	router.GET("/api/supply-chain/analytics",      middleware.RequireAuth(), api.GetSCAnalytics)
	router.GET("/api/supply-chain/compliance",     middleware.RequireAuth(), api.GetSCCompliance)
	router.GET("/api/supply-chain/policies",       middleware.RequireAuth(), api.GetSCPolicies)
	router.POST("/api/supply-chain/policies",      middleware.RequireAuth(), api.PostSCPolicy)
	router.POST("/api/supply-chain/ai",            middleware.RequireAuth(), api.PostSCAI)
	router.POST("/api/supply-chain/response",      middleware.RequireAuth(), api.PostSCResponse)
	router.POST("/api/supply-chain/report",        middleware.RequireAuth(), api.PostSCReport)
	router.PATCH("/api/supply-chain/policies/:id", middleware.RequireAuth(), api.PatchSCPolicy)
	router.DELETE("/api/supply-chain/policies/:id",middleware.RequireAuth(), api.DeleteSCPolicy)

	// ── Active Directory Security Enterprise ─────────────────────────────────
	router.GET("/api/ad/dashboard",         middleware.RequireAuth(), api.GetADDashboard)
	router.GET("/api/ad/inventory",         middleware.RequireAuth(), api.GetADInventory)
	router.GET("/api/ad/identity-risk",     middleware.RequireAuth(), api.GetADIdentityRisk)
	router.GET("/api/ad/auth-monitor",      middleware.RequireAuth(), api.GetADAuthMonitor)
	router.GET("/api/ad/attacks",           middleware.RequireAuth(), api.GetADAttacks)
	router.GET("/api/ad/gpo-changes",       middleware.RequireAuth(), api.GetADGPOChanges)
	router.GET("/api/ad/changes",           middleware.RequireAuth(), api.GetADChanges)
	router.GET("/api/ad/attack-paths",      middleware.RequireAuth(), api.GetADAttackPaths)
	router.GET("/api/ad/tiering",           middleware.RequireAuth(), api.GetADTiering)
	router.GET("/api/ad/exposure",          middleware.RequireAuth(), api.GetADExposure)
	router.GET("/api/ad/threat-intel",      middleware.RequireAuth(), api.GetADThreatIntel)
	router.GET("/api/ad/timeline",          middleware.RequireAuth(), api.GetADTimeline)
	router.GET("/api/ad/graph",             middleware.RequireAuth(), api.GetADRelationshipGraph)
	router.GET("/api/ad/analytics",         middleware.RequireAuth(), api.GetADAnalytics)
	router.GET("/api/ad/assessment",        middleware.RequireAuth(), api.GetADAssessment)
	router.POST("/api/ad/ai",               middleware.RequireAuth(), api.PostADAI)
	router.POST("/api/ad/response",         middleware.RequireAuth(), api.PostADResponse)
	router.POST("/api/ad/report",           middleware.RequireAuth(), api.PostADReport)

	// ── Container Security / Kubernetes Enterprise ───────────────────────────
	router.GET("/api/containers/dashboard",         middleware.RequireAuth(), api.GetContainerDashboard)
	router.GET("/api/containers/clusters",          middleware.RequireAuth(), api.GetK8sClusters)
	router.GET("/api/containers/nodes",             middleware.RequireAuth(), api.GetK8sNodes)
	router.GET("/api/containers/namespaces",        middleware.RequireAuth(), api.GetK8sNamespaces)
	router.GET("/api/containers/pods",              middleware.RequireAuth(), api.GetK8sPods)
	router.GET("/api/containers/images",            middleware.RequireAuth(), api.GetK8sImages)
	router.GET("/api/containers/supply-chain",      middleware.RequireAuth(), api.GetSupplyChain)
	router.GET("/api/containers/runtime-alerts",    middleware.RequireAuth(), api.GetRuntimeAlerts)
	router.GET("/api/containers/rbac",              middleware.RequireAuth(), api.GetK8sRBAC)
	router.GET("/api/containers/secrets",           middleware.RequireAuth(), api.GetK8sSecrets)
	router.GET("/api/containers/network-policies",  middleware.RequireAuth(), api.GetNetworkPolicies)
	router.GET("/api/containers/admission",         middleware.RequireAuth(), api.GetAdmissionControl)
	router.GET("/api/containers/compliance",        middleware.RequireAuth(), api.GetContainerCompliance)
	router.GET("/api/containers/threat-intel",      middleware.RequireAuth(), api.GetContainerThreatIntel)
	router.GET("/api/containers/timeline",          middleware.RequireAuth(), api.GetContainerTimeline)
	router.GET("/api/containers/vulnerabilities",   middleware.RequireAuth(), api.GetContainerVulns)
	router.GET("/api/containers/attack-paths",      middleware.RequireAuth(), api.GetContainerAttackPaths)
	router.GET("/api/containers/analytics",         middleware.RequireAuth(), api.GetContainerAnalytics)
	router.POST("/api/containers/response",         middleware.RequireAuth(), api.PostContainerResponse)
	router.POST("/api/containers/ai",               middleware.RequireAuth(), api.PostContainerAI)
	router.POST("/api/containers/report",           middleware.RequireAuth(), api.PostContainerReport)

	// ── Email Security Enterprise ─────────────────────────────────────────────
	// Static routes before /:id
	router.GET("/api/email/dashboard",          middleware.RequireAuth(), api.GetEmailDashboard)
	router.GET("/api/email/mail-flow",          middleware.RequireAuth(), api.GetEmailMailFlow)
	router.GET("/api/email/messages",           middleware.RequireAuth(), api.GetEmailMessages)
	router.GET("/api/email/threats",            middleware.RequireAuth(), api.GetEmailThreats)
	router.GET("/api/email/attachments",        middleware.RequireAuth(), api.GetEmailAttachments)
	router.GET("/api/email/urls",               middleware.RequireAuth(), api.GetEmailURLs)
	router.GET("/api/email/auth-results",       middleware.RequireAuth(), api.GetEmailAuthResults)
	router.GET("/api/email/sender-intel",       middleware.RequireAuth(), api.GetSenderIntelligence)
	router.GET("/api/email/threat-intel",       middleware.RequireAuth(), api.GetEmailThreatIntel)
	router.GET("/api/email/campaigns",          middleware.RequireAuth(), api.GetEmailCampaigns)
	router.GET("/api/email/timeline",           middleware.RequireAuth(), api.GetEmailTimeline)
	router.GET("/api/email/user-risk",          middleware.RequireAuth(), api.GetEmailUserRisk)
	router.GET("/api/email/analytics",          middleware.RequireAuth(), api.GetEmailAnalytics)
	router.GET("/api/email/policies",           middleware.RequireAuth(), api.GetEmailPolicies)
	router.POST("/api/email/policies",          middleware.RequireAuth(), api.PostEmailPolicy)
	router.GET("/api/email/reported",           middleware.RequireAuth(), api.GetUserReported)
	router.POST("/api/email/ai",                middleware.RequireAuth(), api.PostEmailAI)
	router.POST("/api/email/response",          middleware.RequireAuth(), api.PostEmailResponse)
	router.POST("/api/email/report",            middleware.RequireAuth(), api.PostEmailReport)
	// Parameterized
	router.PATCH("/api/email/policies/:id",     middleware.RequireAuth(), api.PatchEmailPolicy)
	router.DELETE("/api/email/policies/:id",    middleware.RequireAuth(), api.DeleteEmailPolicy)
	router.PATCH("/api/email/reported/:id",     middleware.RequireAuth(), api.PatchUserReported)

	// ── Cloud Security Enterprise ─────────────────────────────────────────────
	// Static routes before /:id
	router.GET("/api/cloud/dashboard",          middleware.RequireAuth(), api.GetCloudDashboard)
	router.GET("/api/cloud/accounts",           middleware.RequireAuth(), api.GetCloudAccounts)
	router.POST("/api/cloud/accounts",          middleware.RequireAuth(), api.PostCloudAccount)
	router.GET("/api/cloud/inventory",          middleware.RequireAuth(), api.GetCloudInventory)
	router.GET("/api/cloud/cspm/findings",      middleware.RequireAuth(), api.GetCSPMFindings)
	router.GET("/api/cloud/cspm/summary",       middleware.RequireAuth(), api.GetCSPMSummary)
	router.GET("/api/cloud/ciem/identities",    middleware.RequireAuth(), api.GetCIEMIdentities)
	router.GET("/api/cloud/ciem/risks",         middleware.RequireAuth(), api.GetCIEMRisks)
	router.GET("/api/cloud/threats",            middleware.RequireAuth(), api.GetCloudThreats)
	router.GET("/api/cloud/exposure",           middleware.RequireAuth(), api.GetCloudExposure)
	router.GET("/api/cloud/compliance",         middleware.RequireAuth(), api.GetCloudCompliance)
	router.GET("/api/cloud/timeline",           middleware.RequireAuth(), api.GetCloudTimeline)
	router.GET("/api/cloud/attack-paths",       middleware.RequireAuth(), api.GetCloudAttackPaths)
	router.GET("/api/cloud/drift",              middleware.RequireAuth(), api.GetCloudDrift)
	router.GET("/api/cloud/vulnerabilities",    middleware.RequireAuth(), api.GetCloudVulnerabilities)
	router.GET("/api/cloud/threat-intel",       middleware.RequireAuth(), api.GetCloudThreatIntel)
	router.POST("/api/cloud/ai",                middleware.RequireAuth(), api.PostCloudAI)
	router.GET("/api/cloud/analytics",          middleware.RequireAuth(), api.GetCloudAnalytics)
	router.POST("/api/cloud/response",          middleware.RequireAuth(), api.PostCloudResponse)
	router.POST("/api/cloud/report",            middleware.RequireAuth(), api.PostCloudReport)
	// Parameterized
	router.DELETE("/api/cloud/accounts/:id",    middleware.RequireAuth(), api.DeleteCloudAccount)
	router.PATCH("/api/cloud/cspm/findings/:id",middleware.RequireAuth(), api.PatchCloudFinding)
	router.PATCH("/api/cloud/drift/:id",        middleware.RequireAuth(), api.PatchCloudDrift)

	// ── Deception Enterprise ──────────────────────────────────────────────────
	// Static routes before /:id
	router.GET("/api/deception/dashboard",          middleware.RequireAuth(), api.GetDeceptionDashboard)
	router.GET("/api/deception/decoys",             middleware.RequireAuth(), api.GetDeceptionDecoys)
	router.POST("/api/deception/decoys",            middleware.RequireAuth(), api.PostDeceptionDecoy)
	router.POST("/api/deception/deploy",            middleware.RequireAuth(), api.PostDeceptionDeploy)
	router.GET("/api/deception/honeytokens",        middleware.RequireAuth(), api.GetDeceptionHoneytokens)
	router.POST("/api/deception/honeytokens",       middleware.RequireAuth(), api.PostDeceptionHoneytoken)
	router.GET("/api/deception/triggers",           middleware.RequireAuth(), api.GetDeceptionTriggers)
	router.GET("/api/deception/campaigns",          middleware.RequireAuth(), api.GetDeceptionCampaigns)
	router.GET("/api/deception/timeline",           middleware.RequireAuth(), api.GetDeceptionTimeline)
	router.GET("/api/deception/graph",              middleware.RequireAuth(), api.GetDeceptionGraph)
	router.GET("/api/deception/threat-intel",       middleware.RequireAuth(), api.GetDeceptionThreatIntel)
	router.POST("/api/deception/ai",                middleware.RequireAuth(), api.PostDeceptionAI)
	router.GET("/api/deception/health",             middleware.RequireAuth(), api.GetDeceptionHealth)
	router.POST("/api/deception/response",          middleware.RequireAuth(), api.PostDeceptionResponse)
	router.GET("/api/deception/analytics",          middleware.RequireAuth(), api.GetDeceptionAnalytics)
	router.GET("/api/deception/watchlists",         middleware.RequireAuth(), api.GetDeceptionWatchlists)
	router.POST("/api/deception/watchlists",        middleware.RequireAuth(), api.PostDeceptionWatchlist)
	router.GET("/api/deception/policies",           middleware.RequireAuth(), api.GetDeceptionPolicies)
	router.POST("/api/deception/policies",          middleware.RequireAuth(), api.PostDeceptionPolicy)
	router.POST("/api/deception/report",            middleware.RequireAuth(), api.PostDeceptionReport)
	router.GET("/api/deception/templates",          middleware.RequireAuth(), api.GetDeceptionTemplates)
	// Parameterized routes
	router.PATCH("/api/deception/decoys/:id",       middleware.RequireAuth(), api.PatchDeceptionDecoy)
	router.DELETE("/api/deception/decoys/:id",      middleware.RequireAuth(), api.DeleteDeceptionDecoy)
	router.DELETE("/api/deception/honeytokens/:id", middleware.RequireAuth(), api.DeleteDeceptionHoneytoken)
	router.DELETE("/api/deception/watchlists/:id",  middleware.RequireAuth(), api.DeleteDeceptionWatchlist)
	router.DELETE("/api/deception/policies/:id",    middleware.RequireAuth(), api.DeleteDeceptionPolicy)

}
