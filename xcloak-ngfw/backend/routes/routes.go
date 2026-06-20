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
	router.DELETE("/api/firewall/rules/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.DeleteRule)

	// ── Auth ──────────────────────────────────────────────────────
	router.POST("/api/auth/register", middleware.RateLimitAuth(), api.Register)
	router.POST("/api/auth/login", middleware.RateLimitAuth(), api.Login)

	// ── Audit ─────────────────────────────────────────────────────
	router.GET("/api/audit/logs", middleware.RequireAuth(), api.GetAuditLogs)
	router.GET("/api/audit/logs/paginated", middleware.RequireAuth(), middleware.RateLimitAPI(), api.GetAuditLogsPaginatedHandler)
	router.GET("/api/audit/export/status", middleware.RequireAuth(), api.GetAuditExportStatusHandler)

	// ── Agents — STATIC routes MUST come before :id wildcard ─────
	router.POST("/api/agents/register", api.RegisterAgent)
	router.POST("/api/agents/heartbeat", middleware.RequireAgentAuth(), api.Heartbeat)
	router.POST("/api/agents/logs", middleware.RequireAgentAuth(), api.ReceiveLogs)
	router.POST("/api/agents/processes",     middleware.RequireAgentAuth(), api.ReceiveProcesses)
	router.POST("/api/agents/audit-events",  middleware.RequireAgentAuth(), api.ReceiveAuditEvents)
	router.POST("/api/agents/registry",      middleware.RequireAgentAuth(), api.ReceiveRegistry)
	router.POST("/api/agents/connections", middleware.RequireAgentAuth(), api.ReceiveConnections)
	router.POST("/api/agents/services", middleware.RequireAgentAuth(), api.ReceiveServices)
	router.POST("/api/agents/packages", middleware.RequireAgentAuth(), api.ReceivePackages)
	router.POST("/api/agents/users", middleware.RequireAgentAuth(), api.ReceiveUsers)
	router.POST("/api/agents/file", middleware.RequireAgentAuth(), api.ReceiveFile)
	router.POST("/api/agents/quarantine", middleware.RequireAgentAuth(), api.ReceiveQuarantinedFile)
	router.POST("/api/agents/fim", middleware.RequireAgentAuth(), api.ReceiveFIMScan)

	router.GET("/api/agents/health", middleware.RequireAuth(), api.GetAgentHealthScores)
	router.POST("/api/agents/health/refresh", middleware.RequireAuth(), middleware.RequireRole("admin"), api.RefreshAgentHealth)

	router.GET("/api/agents", middleware.RequireAuth(), api.GetAgents)

	// ── Agents — :id wildcard routes ─────────────────────────────
	router.GET("/api/agents/:id", middleware.RequireAuth(), api.GetAgentByID)
	router.GET("/api/agents/:id/summary", middleware.RequireAuth(), api.GetAgentSummary)
	router.GET("/api/agents/:id/risk", middleware.RequireAuth(), api.GetRiskScore)
	router.GET("/api/agents/:id/timeline", middleware.RequireAuth(), api.GetAgentTimeline)
	router.GET("/api/agents/:id/vulnerabilities", middleware.RequireAuth(), api.GetAgentVulnerabilities)
	router.POST("/api/agents/:id/vulnerability-scan", middleware.RequireAuth(), middleware.RequireRole("admin"), api.ScanAgentVulnerabilities)
	router.GET("/api/agents/:id/filehashes", middleware.RequireAuth(), api.GetAgentFileHashes)
	router.GET("/api/agents/:id/processes", middleware.RequireAuth(), api.GetAgentProcesses)
	router.GET("/api/agents/:id/connections",   middleware.RequireAuth(), api.GetAgentConnections)
	router.GET("/api/agents/:id/audit-events", middleware.RequireAuth(), api.GetAuditEvents)
	router.GET("/api/agents/:id/registry",    middleware.RequireAuth(), api.GetRegistryEntries)
	router.GET("/api/audit-events/threats",    middleware.RequireAuth(), api.GetThreatAuditEvents)
	router.GET("/api/agents/:id/services", middleware.RequireAuth(), api.GetAgentServicesList)
	router.GET("/api/agents/:id/users", middleware.RequireAuth(), api.GetAgentUsersList)
	router.GET("/api/agents/:id/packages", middleware.RequireAuth(), api.GetAgentPackagesList)
	router.GET("/api/agents/:id/fim/baseline", middleware.RequireAuth(), api.GetFIMBaseline)
	router.GET("/api/agents/:id/fim/alerts", middleware.RequireAuth(), api.GetFIMAlerts)
	router.GET("/api/agents/:id/logs/stream", middleware.RequireAuth(), api.LiveLogsWS) // WS — was wrongly named LiveLogsSSE

	// ── Dashboard ─────────────────────────────────────────────────
	router.GET("/api/dashboard/overview", middleware.RequireAuth(), api.DashboardOverview)

	// ── Tasks ─────────────────────────────────────────────────────
	router.POST("/api/tasks", middleware.RequireAuth(), api.CreateTask)
	router.GET("/api/tasks/agent/:id", middleware.RequireAgentAuth(), api.GetAgentTasks)
	router.POST("/api/tasks/result", middleware.RequireAgentAuth(), api.SubmitTaskResult)
	router.GET("/api/tasks/pending-approval", middleware.RequireAuth(), api.GetPendingApprovalTasks)
	router.POST("/api/tasks/:id/approve", middleware.RequireAuth(), middleware.RequireRole("admin"), api.ApproveTask)
	router.POST("/api/tasks/:id/reject", middleware.RequireAuth(), middleware.RequireRole("admin"), api.RejectTask)

	// ── Alerts ───────────────────────────────────────────────────
	router.GET("/api/alerts", middleware.RequireAuth(), api.GetAlerts)
	router.GET("/api/alerts/paginated", middleware.RequireAuth(), middleware.RateLimitAPI(), api.GetAlertsPaginated)

	// ── Incidents ────────────────────────────────────────────────
	router.GET("/api/incidents", middleware.RequireAuth(), api.GetIncidents)
	router.GET("/api/incidents/paginated", middleware.RequireAuth(), middleware.RateLimitAPI(), api.GetIncidentsPaginated)
	router.GET("/api/incidents/:id/events", middleware.RequireAuth(), api.GetIncidentEvents)
	router.PUT("/api/incidents/:id/status", middleware.RequireAuth(), api.UpdateIncidentStatus)

	// ── Quarantine ───────────────────────────────────────────────
	router.GET("/api/quarantine", middleware.RequireAuth(), api.GetQuarantinedFiles)

	// ── Sigma rules ──────────────────────────────────────────────
	router.POST("/api/sigma/rules", middleware.RequireAuth(), middleware.RequireRole("admin"), api.CreateSigmaRule)
	router.GET("/api/sigma/rules", middleware.RequireAuth(), api.GetSigmaRules)
	router.GET("/api/sigma/rules/:id", middleware.RequireAuth(), api.GetSigmaRuleByID)
	router.PUT("/api/sigma/rules/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.UpdateSigmaRule)
	router.DELETE("/api/sigma/rules/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.DeleteSigmaRule)
	router.PATCH("/api/sigma/rules/:id/enable", middleware.RequireAuth(), middleware.RequireRole("admin"), api.EnableSigmaRule)
	router.PATCH("/api/sigma/rules/:id/disable", middleware.RequireAuth(), middleware.RequireRole("admin"), api.DisableSigmaRule)
	router.POST("/api/sigma/rules/test", middleware.RequireAuth(), api.TestRules)

	// ── IOCs ──────────────────────────────────────────────────────
	router.POST("/api/iocs", middleware.RequireAuth(), middleware.RequireRole("admin"), api.CreateIOC)
	router.GET("/api/iocs", middleware.RequireAuth(), api.GetIOCs)
	router.GET("/api/iocs/:id", middleware.RequireAuth(), api.GetIOCByID)
	router.PUT("/api/iocs/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.UpdateIOC)
	router.DELETE("/api/iocs/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.DeleteIOC)
	router.PATCH("/api/iocs/:id/enable", middleware.RequireAuth(), middleware.RequireRole("admin"), api.EnableIOC)
	router.PATCH("/api/iocs/:id/disable", middleware.RequireAuth(), middleware.RequireRole("admin"), api.DisableIOC)
	router.POST("/api/iocs/import", middleware.RequireAuth(), middleware.RequireRole("admin"), api.ImportIOCs)

	// ── File hashes ───────────────────────────────────────────────
	router.POST("/api/filehashes", middleware.RequireAgentAuth(), api.SaveFileHashes)

	// ── Threat feeds ──────────────────────────────────────────────
	router.POST("/api/threat-feeds", middleware.RequireAuth(), middleware.RequireRole("admin"), api.CreateThreatFeed)
	router.GET("/api/threat-feeds", middleware.RequireAuth(), api.GetThreatFeeds)
	router.POST("/api/threat-feeds/:id/sync", middleware.RequireAuth(), middleware.RequireRole("admin"), api.SyncThreatFeed)

	// ── YARA ──────────────────────────────────────────────────────
	router.POST("/api/yara/matches", middleware.RequireAgentAuth(), api.ReceiveYaraMatches)
	router.GET("/api/yara/matches", middleware.RequireAuth(), api.GetYaraMatches)
	router.POST("/api/yara/rules", middleware.RequireAuth(), middleware.RequireRole("admin"), api.CreateYaraRule)
	router.GET("/api/yara/rules", middleware.RequireAuth(), api.GetYaraRules)
	router.GET("/api/yara/rules/enabled", middleware.RequireAgentAuth(), api.GetEnabledYaraRules)
	router.PUT("/api/yara/rules/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.UpdateYaraRule)
	router.DELETE("/api/yara/rules/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.DeleteYaraRule)
	router.PATCH("/api/yara/rules/:id/enable", middleware.RequireAuth(), middleware.RequireRole("admin"), api.EnableYaraRule)
	router.PATCH("/api/yara/rules/:id/disable", middleware.RequireAuth(), middleware.RequireRole("admin"), api.DisableYaraRule)

	// ── Playbooks ─────────────────────────────────────────────────
	router.POST("/api/playbooks", middleware.RequireAuth(), middleware.RequireRole("admin"), api.CreatePlaybook)
	router.GET("/api/playbooks", middleware.RequireAuth(), api.GetPlaybooks)
	router.PUT("/api/playbooks/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.UpdatePlaybook)
	router.DELETE("/api/playbooks/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.DeletePlaybook)
	router.PATCH("/api/playbooks/:id/enable", middleware.RequireAuth(), middleware.RequireRole("admin"), api.EnablePlaybook)
	router.PATCH("/api/playbooks/:id/disable", middleware.RequireAuth(), middleware.RequireRole("admin"), api.DisablePlaybook)
	router.GET("/api/playbooks/:id/actions", middleware.RequireAuth(), api.GetPlaybookActions)
	router.POST("/api/playbook-actions", middleware.RequireAuth(), middleware.RequireRole("admin"), api.CreatePlaybookAction)
	router.DELETE("/api/playbook-actions/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.DeletePlaybookAction)
	router.GET("/api/playbook-executions", middleware.RequireAuth(), api.GetPlaybookExecutions)

	// ── Suppression ───────────────────────────────────────────────  ← WAS MISSING
	router.GET("/api/suppression/rules", middleware.RequireAuth(), api.GetSuppressionRules)
	router.POST("/api/suppression/rules", middleware.RequireAuth(), middleware.RequireRole("admin"), api.CreateSuppressionRule)
	router.DELETE("/api/suppression/rules/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.DeleteSuppressionRule)
	router.PATCH("/api/suppression/rules/:id/toggle", middleware.RequireAuth(), middleware.RequireRole("admin"), api.ToggleSuppressionRule)

	// ── Compliance ────────────────────────────────────────────────
	router.POST("/api/compliance/reports", middleware.RequireAuth(), middleware.RequireRole("admin"), api.GenerateReport)
	router.GET("/api/compliance/reports", middleware.RequireAuth(), api.GetReports)
	router.GET("/api/compliance/reports/:id", middleware.RequireAuth(), api.GetReport)
	router.DELETE("/api/compliance/reports/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.DeleteReport)

	// ── Exports ───────────────────────────────────────────────────
	router.GET("/api/export/alerts", middleware.RequireAuth(), api.ExportAlertsCSV)
	router.GET("/api/export/incidents", middleware.RequireAuth(), api.ExportIncidentsCSV)
	router.GET("/api/export/vulnerabilities", middleware.RequireAuth(), api.ExportVulnerabilitiesCSV)
	router.GET("/api/export/audit", middleware.RequireAuth(), middleware.RequireRole("admin"), api.ExportAuditJSON)

	// ── CVE ───────────────────────────────────────────────────────
	router.GET("/api/cve/:id", middleware.RequireAuth(), api.GetCVEDetails)

	// ── Users ─────────────────────────────────────────────────────
	router.GET("/api/users", middleware.RequireAuth(), middleware.RequireRole("admin"), api.GetUsers)
	router.PUT("/api/users/:id/role", middleware.RequireAuth(), middleware.RequireRole("admin"), api.UpdateUserRole)
	router.PATCH("/api/users/:id/toggle", middleware.RequireAuth(), middleware.RequireRole("admin"), api.ToggleUserActive)
	router.DELETE("/api/users/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.DeleteUser)

	// ── MITRE ─────────────────────────────────────────────────────
	router.GET("/api/mitre/mappings", middleware.RequireAuth(), api.GetMITREMappings)

	// ── Integrations ──────────────────────────────────────────────
	router.GET("/api/integrations", middleware.RequireAuth(), api.GetIntegrations)
	router.PUT("/api/integrations/:name", middleware.RequireAuth(), middleware.RequireRole("admin"), api.SaveIntegration)
	router.POST("/api/integrations/:name/test", middleware.RequireAuth(), middleware.RequireRole("admin"), api.TestIntegration)
	router.GET("/api/integrations/deliveries", middleware.RequireAuth(), api.GetWebhookDeliveries)
	router.GET("/api/integrations/install-tokens", middleware.RequireAuth(), middleware.RequireRole("admin"), api.GetInstallTokens)
	router.POST("/api/integrations/install-tokens", middleware.RequireAuth(), middleware.RequireRole("admin"), api.GenerateInstallToken)

	// ── AI ────────────────────────────────────────────────────────
	router.POST("/api/ai/triage/:id", middleware.RequireAuth(), api.TriageAlertHandler)
	router.POST("/api/ai/incidents/:id/summarize", middleware.RequireAuth(), api.SummarizeIncidentHandler)
	router.POST("/api/ai/anomaly/:agent_id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.RunAnomalyDetectionHandler)
	router.GET("/api/ai/anomalies", middleware.RequireAuth(), api.GetAnomaliesHandler)
	router.POST("/api/ai/chat", middleware.RequireAuth(), api.AIChatHandler)
	router.GET("/api/ai/chat/history", middleware.RequireAuth(), api.GetChatHistoryHandler)
	router.DELETE("/api/ai/chat/history", middleware.RequireAuth(), api.ClearChatHistoryHandler)

	// ── WebSocket notification stream (registered in main.go) ────
	// router.GET("/api/notifications/stream", ...) — kept in main.go

	// ── Auto-added missing routes ───────────────────────────
	router.GET("/api/agents/:id/tasks", middleware.RequireAuth(), api.GetAgentTaskHistory)
	router.GET("/api/agents/:id/auth-logs", middleware.RequireAuth(), api.GetAgentAuthLogs)
	router.GET("/api/agents/:id/risk/breakdown", middleware.RequireAuth(), api.GetAgentRiskBreakdown)
	router.GET("/api/scheduler/tasks", middleware.RequireAuth(), api.GetScheduledTasks)
	router.POST("/api/scheduler/tasks", middleware.RequireAuth(), middleware.RequireRole("admin"), api.CreateScheduledTask)
	router.PATCH("/api/scheduler/tasks/:id/toggle", middleware.RequireAuth(), middleware.RequireRole("admin"), api.ToggleScheduledTask)
	router.POST("/api/scheduler/tasks/:id/run", middleware.RequireAuth(), middleware.RequireRole("admin"), api.RunScheduledTaskNow)
	router.DELETE("/api/scheduler/tasks/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.DeleteScheduledTask)
	router.GET("/api/dashboard/metrics", middleware.RequireAuth(), api.GetDashboardMetrics)
	router.GET("/api/correlation/rules", middleware.RequireAuth(), api.GetCorrelationRules)
	router.POST("/api/correlation/rules", middleware.RequireAuth(), middleware.RequireRole("admin"), api.CreateCorrelationRule)
	router.PATCH("/api/correlation/rules/:id/toggle", middleware.RequireAuth(), middleware.RequireRole("admin"), api.ToggleCorrelationRule)
	router.DELETE("/api/correlation/rules/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.DeleteCorrelationRule)
	router.GET("/api/hunt/run", middleware.RequireAuth(), api.RunHunt)
	router.POST("/api/hunt/run", middleware.RequireAuth(), api.RunHunt)
	router.GET("/api/hunt/queries", middleware.RequireAuth(), api.GetHuntQueries)
	router.GET("/api/search", middleware.RequireAuth(), api.GlobalSearch)
	router.POST("/api/yara/import", middleware.RequireAuth(), middleware.RequireRole("admin"), api.ImportYARAFiles)
	router.POST("/api/sigma/import", middleware.RequireAuth(), middleware.RequireRole("admin"), api.ImportSigmaYAML)
	router.GET("/api/compliance/reports/:id/scores", middleware.RequireAuth(), api.GetComplianceFrameworkScores)
	router.POST("/api/incidents/:id/notes", middleware.RequireAuth(), api.AddIncidentNote)
	router.GET("/api/incidents/:id/deepdive", middleware.RequireAuth(), api.GetIncidentDeepDive)
	router.POST("/api/alerts/:id/acknowledge", middleware.RequireAuth(), api.AcknowledgeAlert)
	router.POST("/api/alerts/:id/resolve", middleware.RequireAuth(), api.ResolveAlert)
	router.POST("/api/alerts/bulk-acknowledge", middleware.RequireAuth(), api.BulkAcknowledgeAlerts)
	router.POST("/api/alerts/:id/respond", middleware.RequireAuth(), api.DispatchAlertResponse)
	router.GET("/api/alerts/:id", middleware.RequireAuth(), api.GetAlertWithTriage)
	router.POST("/api/iocs/bulk", middleware.RequireAuth(), middleware.RequireRole("admin"), api.BulkImportIOCs)
	router.POST("/api/firewall/sync", middleware.RequireAuth(), middleware.RequireRole("admin"), api.SyncFirewallRules)
	router.GET("/api/firewall/sync/log", middleware.RequireAuth(), api.GetFirewallSyncLog)
	router.POST("/api/scripts/run", middleware.RequireAuth(), middleware.RequireRole("admin"), api.DispatchScript)
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
	router.DELETE("/api/quarantine/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.ReleaseQuarantinedFile)
	router.POST("/api/quarantine", middleware.RequireAuth(), middleware.RequireRole("admin"), api.ReceiveQuarantinedFile)
	router.GET("/api/notifications/email", middleware.RequireAuth(), api.GetEmailRules)
	router.POST("/api/notifications/email", middleware.RequireAuth(), middleware.RequireRole("admin"), api.CreateEmailRule)
	router.PATCH("/api/notifications/email/:id/toggle", middleware.RequireAuth(), middleware.RequireRole("admin"), api.ToggleEmailRule)
	router.DELETE("/api/notifications/email/:id", middleware.RequireAuth(), middleware.RequireRole("admin"), api.DeleteEmailRule)
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
