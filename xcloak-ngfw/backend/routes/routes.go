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
		api.Heartbeat,
	)

	router.POST(
		"/api/tasks",
		middleware.RequireAuth(),
		api.CreateTask,
	)

	router.GET(
		"/api/tasks/agent/:id",
		api.GetAgentTasks,
	)

	router.POST(
		"/api/tasks/result",
		api.SubmitTaskResult,
	)

	router.POST(
		"/api/agents/processes",
		api.ReceiveProcesses,
	)

	router.POST(
		"/api/agents/connections",
		api.ReceiveConnections,
	)

	router.POST(
		"/api/agents/services",
		api.ReceiveServices,
	)

	router.POST(
		"/api/agents/packages",
		api.ReceivePackages,
	)

	router.POST(
		"/api/agents/users",
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
		api.ReceiveLogs,
	)

	router.GET(
		"/api/alerts",
		middleware.RequireAuth(),
		api.GetAlerts,
	)

	router.POST(
		"/api/agents/file",
		api.ReceiveFile,
	)

	router.POST(
		"/api/agents/quarantine",
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

	router.GET(
		"/api/agents/:id/filehashes",
		middleware.RequireAuth(),
		api.GetAgentFileHashes,
	)

}
