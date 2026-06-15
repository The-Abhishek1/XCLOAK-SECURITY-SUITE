package services

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"xcloak-ngfw/database"
)

// ── Gauge metrics (current state) ────────────────────────────
var (
	AgentsTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xcloak_agents_total",
		Help: "Total registered agents",
	})
	AgentsOnline = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xcloak_agents_online",
		Help: "Agents currently online",
	})
	AlertsTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xcloak_alerts_total",
		Help: "Total alerts in database",
	})
	AlertsCritical = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xcloak_alerts_critical",
		Help: "Critical severity alerts",
	})
	AlertsHigh = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xcloak_alerts_high",
		Help: "High severity alerts",
	})
	IncidentsOpen = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xcloak_incidents_open",
		Help: "Open + investigating incidents",
	})
	VulnerabilitiesCritical = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xcloak_vulnerabilities_critical",
		Help: "Critical unpatched CVEs",
	})
	IOCsActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xcloak_iocs_active",
		Help: "Enabled IOC indicators",
	})
	QuarantinedFiles = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xcloak_quarantined_files",
		Help: "Files currently in quarantine",
	})
	ThreatScore = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xcloak_threat_score",
		Help: "Platform-wide threat score 0-100",
	})
	SigmaRulesActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xcloak_sigma_rules_active",
		Help: "Enabled Sigma detection rules",
	})
	YaraRulesActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xcloak_yara_rules_active",
		Help: "Enabled YARA rules",
	})
	AgentTasksPending = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xcloak_agent_tasks_pending",
		Help: "Agent tasks queued but not yet running",
	})
	FIMViolations24h = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xcloak_fim_violations_24h",
		Help: "File integrity violations in last 24 hours",
	})
	YARAMatches24h = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xcloak_yara_matches_24h",
		Help: "YARA rule matches in last 24 hours",
	})
	SOARExecutions24h = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "xcloak_soar_executions_24h",
		Help: "Playbook executions in last 24 hours",
	})
)

// ── Counter metrics (monotonically increasing) ───────────────
var (
	AlertsCreatedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xcloak_alerts_created_total",
		Help: "Alerts created by severity",
	}, []string{"severity"})

	PlaybooksFiredTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xcloak_playbooks_fired_total",
		Help: "Playbook executions by status",
	}, []string{"status"})

	IOCMatchesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "xcloak_ioc_matches_total",
		Help: "Total IOC matches triggered",
	})

	AgentTasksDispatchedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "xcloak_agent_tasks_dispatched_total",
		Help: "Agent tasks dispatched by type",
	}, []string{"task_type"})
)

// RefreshMetrics queries the DB and updates all gauge metrics.
// Call periodically (every 30s) from the scheduler.
func RefreshMetrics() {
	db := database.DB
	if db == nil {
		return
	}

	var v float64

	// Agents
	db.QueryRow(`SELECT COUNT(*) FROM agents`).Scan(&v)
	AgentsTotal.Set(v)
	db.QueryRow(`SELECT COUNT(*) FROM agents WHERE status='online'`).Scan(&v)
	AgentsOnline.Set(v)

	// Alerts
	db.QueryRow(`SELECT COUNT(*) FROM alerts`).Scan(&v)
	AlertsTotal.Set(v)
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE severity='critical'`).Scan(&v)
	AlertsCritical.Set(v)
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE severity='high'`).Scan(&v)
	AlertsHigh.Set(v)

	// Incidents
	db.QueryRow(`SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating')`).Scan(&v)
	IncidentsOpen.Set(v)

	// Vulnerabilities
	db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE severity='critical'`).Scan(&v)
	VulnerabilitiesCritical.Set(v)

	// IOCs
	db.QueryRow(`SELECT COUNT(*) FROM iocs WHERE enabled=TRUE`).Scan(&v)
	IOCsActive.Set(v)

	// Quarantine
	db.QueryRow(`SELECT COUNT(*) FROM quarantine_files`).Scan(&v)
	QuarantinedFiles.Set(v)

	// Rules
	db.QueryRow(`SELECT COUNT(*) FROM sigma_rules WHERE enabled=TRUE`).Scan(&v)
	SigmaRulesActive.Set(v)
	db.QueryRow(`SELECT COUNT(*) FROM yara_rules WHERE enabled=TRUE`).Scan(&v)
	YaraRulesActive.Set(v)

	// Tasks
	db.QueryRow(`SELECT COUNT(*) FROM agent_tasks WHERE status='pending'`).Scan(&v)
	AgentTasksPending.Set(v)

	// Last 24h activity
	db.QueryRow(`SELECT COUNT(*) FROM fim_alerts WHERE created_at > now() - INTERVAL '24h'`).Scan(&v)
	FIMViolations24h.Set(v)
	db.QueryRow(`SELECT COUNT(*) FROM yara_matches WHERE matched_at > now() - INTERVAL '24h'`).Scan(&v)
	YARAMatches24h.Set(v)
	db.QueryRow(`SELECT COUNT(*) FROM playbook_executions WHERE created_at > now() - INTERVAL '24h'`).Scan(&v)
	SOARExecutions24h.Set(v)

	// Compute threat score (reuse existing logic)
	var critAlerts, highAlerts, openInc, critVulns int
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE severity='critical'`).Scan(&critAlerts)
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE severity='high'`).Scan(&highAlerts)
	db.QueryRow(`SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating')`).Scan(&openInc)
	db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE severity='critical'`).Scan(&critVulns)

	score := critAlerts*15 + highAlerts*8 + openInc*20 + critVulns*5
	if score > 100 {
		score = 100
	}
	ThreatScore.Set(float64(score))
}

// IncrementAlertCounter is called from CreateAlert — increments the counter by severity.
func IncrementAlertCounter(severity string) {
	AlertsCreatedTotal.WithLabelValues(severity).Inc()
	if severity == "critical" || severity == "high" {
		if severity == "critical" {
			// Check if it's an IOC match
		}
	}
}

// IncrementPlaybookCounter is called from playbook_engine.go
func IncrementPlaybookCounter(status string) {
	PlaybooksFiredTotal.WithLabelValues(status).Inc()
}

// IncrementTaskCounter is called from CreateTask
func IncrementTaskCounter(taskType string) {
	AgentTasksDispatchedTotal.WithLabelValues(taskType).Inc()
}
