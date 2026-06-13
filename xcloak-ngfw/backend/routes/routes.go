package routes

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/api"
	"xcloak-ngfw/middleware"
)

func SetupRoutes(router *gin.Engine) {

	router.POST(
		"/api/firewall/rules",
		middleware.RequireAuth(),
		api.CreateRule,
	)

	router.GET(
		"/api/firewall/rules",
		middleware.RequireAuth(),
		api.GetRules,
	)

	router.GET(
		"/api/health",
		api.Health,
	)

	router.DELETE(
		"/api/firewall/rules/:id",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.DeleteRule,
	)

	router.GET(
		"/api/firewall/rules/:id",
		middleware.RequireAuth(),
		api.GetRuleByID,
	)

	router.PUT(
		"/api/firewall/rules/:id",
		middleware.RequireAuth(),
		api.UpdateRule,
	)

	router.POST(
		"/api/auth/register",
		api.Register,
	)

	router.POST(
		"/api/auth/login",
		api.Login,
	)

	router.GET(
		"/api/audit/logs",
		middleware.RequireAuth(),
		api.GetAuditLogs,
	)

	router.POST(
		"/api/agents/register",
		api.RegisterAgent,
	)

	router.GET(
		"/api/agents",
		middleware.RequireAuth(),
		api.GetAgents,
	)

	router.GET(
		"/api/agents/:id",
		middleware.RequireAuth(),
		api.GetAgentByID,
	)

	router.POST(
		"/api/agents/heartbeat",
		middleware.RequireAgentAuth(),
		api.Heartbeat,
	)

	router.POST(
		"/api/tasks",
		middleware.RequireAuth(),
		api.CreateTask,
	)

	router.GET(
		"/api/tasks/agent/:id",
		middleware.RequireAgentAuth(),
		api.GetAgentTasks,
	)

	router.POST(
		"/api/tasks/result",
		middleware.RequireAgentAuth(),
		api.SubmitTaskResult,
	)

	router.POST(
		"/api/agents/processes",
		middleware.RequireAgentAuth(),
		api.ReceiveProcesses,
	)

	router.POST(
		"/api/agents/connections",
		middleware.RequireAgentAuth(),
		api.ReceiveConnections,
	)

	router.POST(
		"/api/agents/services",
		middleware.RequireAgentAuth(),
		api.ReceiveServices,
	)

	router.POST(
		"/api/agents/packages",
		middleware.RequireAgentAuth(),
		api.ReceivePackages,
	)

	router.POST(
		"/api/agents/users",
		middleware.RequireAgentAuth(),
		api.ReceiveUsers,
	)
	router.GET(
		"/api/agents/:id/summary",
		middleware.RequireAuth(),
		api.GetAgentSummary,
	)

	router.GET(
		"/api/dashboard/overview",
		middleware.RequireAuth(),
		api.DashboardOverview,
	)

	router.POST(
		"/api/agents/logs",
		middleware.RequireAgentAuth(),
		api.ReceiveLogs,
	)

	router.GET(
		"/api/alerts",
		middleware.RequireAuth(),
		api.GetAlerts,
	)

	router.POST(
		"/api/agents/file",
		middleware.RequireAgentAuth(),
		api.ReceiveFile,
	)

	router.POST(
		"/api/agents/quarantine",
		middleware.RequireAgentAuth(),
		api.ReceiveQuarantinedFile,
	)

	router.GET(
		"/api/quarantine",
		middleware.RequireAuth(),
		api.GetQuarantinedFiles,
	)

	router.GET(
		"/api/incidents",
		middleware.RequireAuth(),
		api.GetIncidents,
	)

	router.GET(
		"/api/incidents/:id/events",
		middleware.RequireAuth(),
		api.GetIncidentEvents,
	)

	router.POST(
		"/api/sigma/rules",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.CreateSigmaRule,
	)

	router.GET(
		"/api/sigma/rules",
		middleware.RequireAuth(),
		api.GetSigmaRules,
	)

	router.GET(
		"/api/sigma/rules/:id",
		middleware.RequireAuth(),
		api.GetSigmaRuleByID,
	)

	router.PUT(
		"/api/sigma/rules/:id",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.UpdateSigmaRule,
	)

	router.DELETE(
		"/api/sigma/rules/:id",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.DeleteSigmaRule,
	)

	router.PATCH(
		"/api/sigma/rules/:id/enable",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.EnableSigmaRule,
	)

	router.PATCH(
		"/api/sigma/rules/:id/disable",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.DisableSigmaRule,
	)

	router.POST(
		"/api/sigma/rules/test",
		middleware.RequireAuth(),
		api.TestRules,
	)

	router.POST(
		"/api/iocs",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.CreateIOC,
	)

	router.GET(
		"/api/iocs",
		middleware.RequireAuth(),
		api.GetIOCs,
	)

	router.GET(
		"/api/iocs/:id",
		middleware.RequireAuth(),
		api.GetIOCByID,
	)

	router.PUT(
		"/api/iocs/:id",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.UpdateIOC,
	)

	router.DELETE(
		"/api/iocs/:id",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.DeleteIOC,
	)

	router.PATCH(
		"/api/iocs/:id/enable",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.EnableIOC,
	)

	router.PATCH(
		"/api/iocs/:id/disable",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.DisableIOC,
	)

	router.POST(
		"/api/filehashes",
		api.SaveFileHashes,
	)

	router.POST(
		"/api/threat-feeds",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.CreateThreatFeed,
	)

	router.GET(
		"/api/threat-feeds",
		middleware.RequireAuth(),
		api.GetThreatFeeds,
	)

	router.POST(
		"/api/iocs/import",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.ImportIOCs,
	)

	router.POST(
		"/api/yara/matches",
		api.ReceiveYaraMatches,
	)

	router.POST(
		"/api/playbooks",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.CreatePlaybook,
	)

	router.GET(
		"/api/playbooks",
		middleware.RequireAuth(),
		api.GetPlaybooks,
	)

	router.POST(
		"/api/playbook-actions",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.CreatePlaybookAction,
	)

	router.GET(
		"/api/playbooks/:id/actions",
		middleware.RequireAuth(),
		api.GetPlaybookActions,
	)

	router.DELETE(
		"/api/playbook-actions/:id",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.DeletePlaybookAction,
	)

	router.GET(
		"/api/playbook-executions",
		middleware.RequireAuth(),
		api.GetPlaybookExecutions,
	)

	router.GET(
		"/api/agents/:id/risk",
		middleware.RequireAuth(),
		api.GetRiskScore,
	)

	router.GET(
		"/api/agents/:id/timeline",
		middleware.RequireAuth(),
		api.GetAgentTimeline,
	)

	router.POST(
		"/api/agents/:id/vulnerability-scan",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.ScanAgentVulnerabilities,
	)

	router.GET(
		"/api/agents/:id/vulnerabilities",
		middleware.RequireAuth(),
		api.GetAgentVulnerabilities,
	)

	router.GET(
		"/api/agents/:id/filehashes",
		middleware.RequireAuth(),
		api.GetAgentFileHashes,
	)

	// ── Agent data list endpoints (NEW) ─────────────────────────────────
	router.GET(
		"/api/agents/:id/processes",
		middleware.RequireAuth(),
		api.GetAgentProcesses,
	)

	router.GET(
		"/api/agents/:id/connections",
		middleware.RequireAuth(),
		api.GetAgentConnections,
	)

	router.GET(
		"/api/agents/:id/services",
		middleware.RequireAuth(),
		api.GetAgentServicesList,
	)

	router.GET(
		"/api/agents/:id/users",
		middleware.RequireAuth(),
		api.GetAgentUsersList,
	)

	router.GET(
		"/api/agents/:id/packages",
		middleware.RequireAuth(),
		api.GetAgentPackagesList,
	)

	// ── Playbook CRUD (NEW) ──────────────────────────────────────────────
	router.PUT(
		"/api/playbooks/:id",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.UpdatePlaybook,
	)

	router.DELETE(
		"/api/playbooks/:id",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.DeletePlaybook,
	)

	router.PATCH(
		"/api/playbooks/:id/enable",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.EnablePlaybook,
	)

	router.PATCH(
		"/api/playbooks/:id/disable",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.DisablePlaybook,
	)

	// ADD THESE ROUTES to xcloak-ngfw/backend/routes/routes.go inside SetupRoutes.

	// ── YARA Rule Management (NEW) ───────────────────────────────────────
	router.POST(
		"/api/yara/rules",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.CreateYaraRule,
	)

	router.GET(
		"/api/yara/rules",
		middleware.RequireAuth(),
		api.GetYaraRules,
	)

	// Agent-facing: fetch only enabled rules before a scan_yara task.
	// Uses RequireAgentAuth so agents authenticate with their bearer token.
	router.GET(
		"/api/yara/rules/enabled",
		middleware.RequireAgentAuth(),
		api.GetEnabledYaraRules,
	)

	router.PUT(
		"/api/yara/rules/:id",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.UpdateYaraRule,
	)

	router.DELETE(
		"/api/yara/rules/:id",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.DeleteYaraRule,
	)

	router.PATCH(
		"/api/yara/rules/:id/enable",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.EnableYaraRule,
	)

	router.PATCH(
		"/api/yara/rules/:id/disable",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.DisableYaraRule,
	)

	// GET /api/yara/matches — list all matches, or ?agent_id=N for one agent.
	router.GET(
		"/api/yara/matches",
		middleware.RequireAuth(),
		api.GetYaraMatches,
	)

	// ── Threat Feed Sync (NEW) ────────────────────────────────────────────
	router.POST(
		"/api/threat-feeds/:id/sync",
		middleware.RequireAuth(),
		middleware.RequireRole("admin"),
		api.SyncThreatFeed,
	)

}
