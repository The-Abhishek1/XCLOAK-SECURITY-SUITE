package services

import (
	"fmt"
	"time"

	"xcloak-ngfw/database"
)

type AlertTrendPoint struct {
	Hour     string `json:"hour"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
}

type MTTRStats struct {
	AvgSeconds   float64 `json:"avg_seconds"`
	AvgFormatted string  `json:"avg_formatted"`
	TotalResolved int    `json:"total_resolved"`
	Last24h      float64 `json:"last_24h_seconds"`
}

type DashboardMetrics struct {
	AlertTrend    []AlertTrendPoint `json:"alert_trend"`
	MTTR          MTTRStats         `json:"mttr"`
	AlertVelocity int               `json:"alert_velocity_1h"` // alerts in last hour
	ThreatScore   int               `json:"threat_score"`      // platform-wide 0-100
	TopRules      []RuleCount       `json:"top_rules"`
	TopAgents     []AgentAlertCount `json:"top_agents"`
}

type RuleCount struct {
	RuleName string `json:"rule_name"`
	Count    int    `json:"count"`
	Severity string `json:"severity"`
}

type AgentAlertCount struct {
	AgentID  int    `json:"agent_id"`
	Hostname string `json:"hostname"`
	Count    int    `json:"count"`
}

func GetDashboardMetrics() (*DashboardMetrics, error) {

	m := &DashboardMetrics{}

	// ── Alert trend (last 24h, hourly) ────────────────────────
	rows, err := database.DB.Query(`
		SELECT
			to_char(date_trunc('hour', created_at), 'HH24:MI') AS hour,
			COALESCE(SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END), 0) AS critical,
			COALESCE(SUM(CASE WHEN severity='high'     THEN 1 ELSE 0 END), 0) AS high,
			COALESCE(SUM(CASE WHEN severity='medium'   THEN 1 ELSE 0 END), 0) AS medium,
			COALESCE(SUM(CASE WHEN severity='low'      THEN 1 ELSE 0 END), 0) AS low
		FROM alerts
		WHERE created_at > now() - INTERVAL '24 hours'
		GROUP BY date_trunc('hour', created_at)
		ORDER BY date_trunc('hour', created_at) ASC
	`)

	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p AlertTrendPoint
			if err := rows.Scan(&p.Hour, &p.Critical, &p.High, &p.Medium, &p.Low); err == nil {
				m.AlertTrend = append(m.AlertTrend, p)
			}
		}
	}

	// ── MTTR ──────────────────────────────────────────────────
	database.DB.QueryRow(`
		SELECT
			COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))), 0),
			COUNT(*) FILTER (WHERE resolved_at IS NOT NULL)
		FROM incidents
		WHERE resolved_at IS NOT NULL
	`).Scan(&m.MTTR.AvgSeconds, &m.MTTR.TotalResolved)

	database.DB.QueryRow(`
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))), 0)
		FROM incidents
		WHERE resolved_at IS NOT NULL
		AND created_at > now() - INTERVAL '24 hours'
	`).Scan(&m.MTTR.Last24h)

	m.MTTR.AvgFormatted = formatDuration(m.MTTR.AvgSeconds)

	// ── Alert velocity (last 1h) ───────────────────────────────
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM alerts
		WHERE created_at > now() - INTERVAL '1 hour'
	`).Scan(&m.AlertVelocity)

	// ── Top firing rules (last 7d) ─────────────────────────────
	ruleRows, err := database.DB.Query(`
		SELECT rule_name, severity, COUNT(*) as cnt
		FROM alerts
		WHERE created_at > now() - INTERVAL '7 days'
		GROUP BY rule_name, severity
		ORDER BY cnt DESC
		LIMIT 10
	`)
	if err == nil {
		defer ruleRows.Close()
		for ruleRows.Next() {
			var r RuleCount
			if err := ruleRows.Scan(&r.RuleName, &r.Severity, &r.Count); err == nil {
				m.TopRules = append(m.TopRules, r)
			}
		}
	}

	// ── Top agents by alert count ──────────────────────────────
	agentRows, err := database.DB.Query(`
		SELECT a.id, a.hostname, COUNT(al.id) as cnt
		FROM agents a
		JOIN alerts al ON al.agent_id = a.id
		WHERE al.created_at > now() - INTERVAL '7 days'
		GROUP BY a.id, a.hostname
		ORDER BY cnt DESC
		LIMIT 5
	`)
	if err == nil {
		defer agentRows.Close()
		for agentRows.Next() {
			var aa AgentAlertCount
			if err := agentRows.Scan(&aa.AgentID, &aa.Hostname, &aa.Count); err == nil {
				m.TopAgents = append(m.TopAgents, aa)
			}
		}
	}

	// ── Platform threat score (weighted 0-100) ─────────────────
	var critAlerts, highAlerts, openIncidents, critVulns int
	database.DB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE severity='critical' AND created_at > now() - INTERVAL '24 hours'`).Scan(&critAlerts)
	database.DB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE severity='high' AND created_at > now() - INTERVAL '24 hours'`).Scan(&highAlerts)
	database.DB.QueryRow(`SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating')`).Scan(&openIncidents)
	database.DB.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE severity='critical'`).Scan(&critVulns)

	score := (critAlerts * 5) + (highAlerts * 2) + (openIncidents * 10) + (critVulns * 3)
	if score > 100 {
		score = 100
	}
	m.ThreatScore = score

	return m, nil
}

// RecordMTTR updates resolved_at and mttr_seconds when an incident is closed.
func RecordMTTR(incidentID int) {
	database.DB.Exec(`
		UPDATE incidents
		SET resolved_at = now(),
		    mttr_seconds = EXTRACT(EPOCH FROM (now() - created_at))::BIGINT
		WHERE id = $1 AND resolved_at IS NULL
	`, incidentID)
}

func formatDuration(seconds float64) string {
	if seconds == 0 {
		return "N/A"
	}
	d := time.Duration(seconds) * time.Second
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}
