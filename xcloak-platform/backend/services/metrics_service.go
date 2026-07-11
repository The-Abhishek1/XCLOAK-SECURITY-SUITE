package services

import (
	"fmt"
	"math"
	"time"

	"xcloak-platform/database"
)

// ── Shared types ─────────────────────────────────────────────────────────────

type AlertTrendPoint struct {
	Label    string `json:"label"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
}

type MTTRStats struct {
	AvgSeconds    float64 `json:"avg_seconds"`
	AvgFormatted  string  `json:"avg_formatted"`
	TotalResolved int     `json:"total_resolved"`
	Last24h       float64 `json:"last_24h_seconds"`
}

type MTTDStats struct {
	AvgSeconds   float64 `json:"avg_seconds"`
	AvgFormatted string  `json:"avg_formatted"`
	SampleCount  int     `json:"sample_count"`
}

type TrendDelta struct {
	Current  int     `json:"current"`
	Previous int     `json:"previous"`
	Delta    int     `json:"delta"`
	DeltaPct float64 `json:"delta_pct"` // positive = increase, negative = decrease
}

type AgentCoverage struct {
	Total   int     `json:"total"`
	Online  int     `json:"online"`
	Offline int     `json:"offline"`
	PctOnline float64 `json:"pct_online"`
}

type MitreTacticCount struct {
	Tactic     string `json:"tactic"`
	AlertCount int    `json:"alert_count"`
	Severity   string `json:"severity"` // highest severity seen for this tactic
}

type RuleHealth struct {
	SigmaEnabled  int `json:"sigma_enabled"`
	SigmaDisabled int `json:"sigma_disabled"`
	SigmaTotal    int `json:"sigma_total"`
	YaraEnabled   int `json:"yara_enabled"`
	YaraTotal     int `json:"yara_total"`
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

// ── Main metrics struct ───────────────────────────────────────────────────────

type DashboardMetrics struct {
	// Core trend + velocity
	AlertTrend    []AlertTrendPoint `json:"alert_trend"`
	AlertVelocity int               `json:"alert_velocity_1h"`
	ThreatScore   int               `json:"threat_score"`

	// Operational KPIs
	MTTR MTTRStats `json:"mttr"`
	MTTD MTTDStats `json:"mttd"`

	// Period-over-period deltas (current vs previous same-length period)
	AlertDeltas    TrendDelta `json:"alert_deltas"`
	IncidentDeltas TrendDelta `json:"incident_deltas"`

	// Sensor coverage (like CrowdStrike)
	AgentCoverage AgentCoverage `json:"agent_coverage"`

	// MITRE ATT&CK heatmap (ordered list)
	MitreTactics []MitreTacticCount `json:"mitre_tactics"`

	// Rule health
	RuleHealth     RuleHealth `json:"rule_health"`
	IOCHits        int        `json:"ioc_hits"`
	AnomalyScore   float64    `json:"anomaly_score"`   // 0-1; 1 = today 2× daily average
	ComplianceScore float64   `json:"compliance_score"` // 0-100 average across latest reports

	// Rankings
	TopRules  []RuleCount      `json:"top_rules"`
	TopAgents []AgentAlertCount `json:"top_agents"`

	// Meta
	Range string `json:"range"`
}

// ── Range helpers ─────────────────────────────────────────────────────────────

type rangeConfig struct {
	Interval    string // postgres interval for current window
	BucketTrunc string // date_trunc arg
	BucketLabel string // to_char format
	Points      int    // expected number of trend points
}

func resolveRange(r string) rangeConfig {
	switch r {
	case "1h":
		return rangeConfig{"1 hour", "minute", "HH24:MI", 12} // 5-min buckets via FLOOR trick below
	case "7d":
		return rangeConfig{"7 days", "hour", "MM-DD HH24:00", 28} // 6-hour buckets
	case "30d":
		return rangeConfig{"30 days", "day", "MM-DD", 30}
	default: // 24h
		return rangeConfig{"24 hours", "hour", "HH24:MI", 24}
	}
}

// ── Main function ─────────────────────────────────────────────────────────────

func GetDashboardMetrics(tenantID int, rangeStr string) (*DashboardMetrics, error) {
	if rangeStr == "" {
		rangeStr = "24h"
	}
	rc := resolveRange(rangeStr)
	m := &DashboardMetrics{Range: rangeStr}
	db := database.RDB()

	// ── Alert trend ───────────────────────────────────────────────────────────

	var trendSQL string
	if rangeStr == "7d" {
		// 6-hour buckets for 7d
		trendSQL = fmt.Sprintf(`
			SELECT to_char(date_trunc('hour', created_at) - INTERVAL '1 hour' *
			       (EXTRACT(HOUR FROM date_trunc('hour', created_at))::int %% 6), 'MM-DD HH24:MI') AS lbl,
			       COALESCE(SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END),0),
			       COALESCE(SUM(CASE WHEN severity='high'     THEN 1 ELSE 0 END),0),
			       COALESCE(SUM(CASE WHEN severity='medium'   THEN 1 ELSE 0 END),0),
			       COALESCE(SUM(CASE WHEN severity='low'      THEN 1 ELSE 0 END),0)
			FROM alerts
			WHERE created_at > now() - INTERVAL '%s' AND tenant_id=$1
			GROUP BY lbl ORDER BY lbl ASC`, rc.Interval)
	} else {
		trendSQL = fmt.Sprintf(`
			SELECT to_char(date_trunc('%s', created_at), '%s') AS lbl,
			       COALESCE(SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END),0),
			       COALESCE(SUM(CASE WHEN severity='high'     THEN 1 ELSE 0 END),0),
			       COALESCE(SUM(CASE WHEN severity='medium'   THEN 1 ELSE 0 END),0),
			       COALESCE(SUM(CASE WHEN severity='low'      THEN 1 ELSE 0 END),0)
			FROM alerts
			WHERE created_at > now() - INTERVAL '%s' AND tenant_id=$1
			GROUP BY date_trunc('%s', created_at)
			ORDER BY date_trunc('%s', created_at) ASC`,
			rc.BucketTrunc, rc.BucketLabel, rc.Interval, rc.BucketTrunc, rc.BucketTrunc)
	}
	rows, err := db.Query(trendSQL, tenantID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p AlertTrendPoint
			rows.Scan(&p.Label, &p.Critical, &p.High, &p.Medium, &p.Low)
			m.AlertTrend = append(m.AlertTrend, p)
		}
	}

	// ── MTTR ─────────────────────────────────────────────────────────────────

	db.QueryRow(`
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))), 0),
		       COUNT(*) FILTER (WHERE resolved_at IS NOT NULL)
		FROM incidents
		WHERE resolved_at IS NOT NULL AND tenant_id=$1
	`, tenantID).Scan(&m.MTTR.AvgSeconds, &m.MTTR.TotalResolved)

	db.QueryRow(`
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))), 0)
		FROM incidents
		WHERE resolved_at IS NOT NULL AND created_at > now() - INTERVAL '24 hours' AND tenant_id=$1
	`, tenantID).Scan(&m.MTTR.Last24h)

	m.MTTR.AvgFormatted = formatDuration(m.MTTR.AvgSeconds)

	// ── MTTD (Mean Time to Detect) ────────────────────────────────────────────
	// Proxy: time from earliest alert on an agent to when an incident opened for it.

	db.QueryRow(`
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (i.created_at - a.first_alert))), 0),
		       COUNT(*)
		FROM incidents i
		JOIN (
		    SELECT agent_id, MIN(created_at) as first_alert
		    FROM alerts
		    WHERE severity IN ('critical','high')
		    GROUP BY agent_id
		) a ON a.agent_id = i.agent_id
		WHERE i.tenant_id = $1
		  AND i.created_at > now() - INTERVAL '30 days'
		  AND a.first_alert < i.created_at
		  AND EXTRACT(EPOCH FROM (i.created_at - a.first_alert)) > 0
	`, tenantID).Scan(&m.MTTD.AvgSeconds, &m.MTTD.SampleCount)

	m.MTTD.AvgFormatted = formatDuration(m.MTTD.AvgSeconds)

	// ── Alert velocity (last 1h) ──────────────────────────────────────────────

	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE created_at > now() - INTERVAL '1 hour' AND tenant_id=$1`, tenantID).Scan(&m.AlertVelocity)

	// ── Period-over-period deltas ─────────────────────────────────────────────

	db.QueryRow(fmt.Sprintf(`
		SELECT COUNT(*) FROM alerts
		WHERE created_at > now() - INTERVAL '%s' AND tenant_id=$1`, rc.Interval), tenantID).Scan(&m.AlertDeltas.Current)

	db.QueryRow(fmt.Sprintf(`
		SELECT COUNT(*) FROM alerts
		WHERE created_at BETWEEN now() - INTERVAL '%s' * 2 AND now() - INTERVAL '%s'
		AND tenant_id=$1`, rc.Interval, rc.Interval), tenantID).Scan(&m.AlertDeltas.Previous)

	m.AlertDeltas.Delta = m.AlertDeltas.Current - m.AlertDeltas.Previous
	if m.AlertDeltas.Previous > 0 {
		m.AlertDeltas.DeltaPct = math.Round(float64(m.AlertDeltas.Delta)/float64(m.AlertDeltas.Previous)*100*10) / 10
	}

	db.QueryRow(`SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating') AND tenant_id=$1`, tenantID).Scan(&m.IncidentDeltas.Current)
	db.QueryRow(`SELECT COUNT(*) FROM incidents WHERE status = 'resolved' AND resolved_at > now() - INTERVAL '7 days' AND tenant_id=$1`, tenantID).Scan(&m.IncidentDeltas.Previous)
	m.IncidentDeltas.Delta = m.IncidentDeltas.Current

	// ── Agent coverage ────────────────────────────────────────────────────────

	db.QueryRow(`SELECT COUNT(*) FROM agents WHERE tenant_id=$1`, tenantID).Scan(&m.AgentCoverage.Total)
	db.QueryRow(`SELECT COUNT(*) FROM agents WHERE status='online' AND tenant_id=$1`, tenantID).Scan(&m.AgentCoverage.Online)
	m.AgentCoverage.Offline = m.AgentCoverage.Total - m.AgentCoverage.Online
	if m.AgentCoverage.Total > 0 {
		m.AgentCoverage.PctOnline = math.Round(float64(m.AgentCoverage.Online)/float64(m.AgentCoverage.Total)*100*10) / 10
	}

	// ── MITRE ATT&CK tactic heatmap ───────────────────────────────────────────
	// Return all 14 canonical tactics in kill-chain order; fill from DB.

	tacticOrder := []string{
		"Reconnaissance", "Resource Development", "Initial Access", "Execution",
		"Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
		"Discovery", "Lateral Movement", "Collection", "Command and Control",
		"Exfiltration", "Impact",
	}

	tacticMap := map[string]MitreTacticCount{}
	for _, t := range tacticOrder {
		tacticMap[t] = MitreTacticCount{Tactic: t}
	}

	mitreRows, err := db.Query(fmt.Sprintf(`
		SELECT COALESCE(mitre_tactic,'Unknown') AS tactic,
		       COUNT(*) AS cnt,
		       MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) AS sev_rank
		FROM alerts
		WHERE created_at > now() - INTERVAL '%s'
		  AND tenant_id=$1
		  AND mitre_tactic IS NOT NULL AND mitre_tactic != ''
		GROUP BY mitre_tactic
		ORDER BY cnt DESC`, rc.Interval), tenantID)

	if err == nil {
		defer mitreRows.Close()
		for mitreRows.Next() {
			var tactic string
			var cnt, sevRank int
			if mitreRows.Scan(&tactic, &cnt, &sevRank) == nil {
				sev := "low"
				switch sevRank {
				case 4:
					sev = "critical"
				case 3:
					sev = "high"
				case 2:
					sev = "medium"
				}
				if _, known := tacticMap[tactic]; known {
					tacticMap[tactic] = MitreTacticCount{Tactic: tactic, AlertCount: cnt, Severity: sev}
				} else {
					// Non-standard tactic label — still include it
					m.MitreTactics = append(m.MitreTactics, MitreTacticCount{Tactic: tactic, AlertCount: cnt, Severity: sev})
				}
			}
		}
	}

	for _, t := range tacticOrder {
		m.MitreTactics = append(m.MitreTactics, tacticMap[t])
	}

	// ── Rule health ───────────────────────────────────────────────────────────

	db.QueryRow(`SELECT COUNT(*) FILTER (WHERE enabled), COUNT(*) FROM sigma_rules WHERE tenant_id=$1`, tenantID).
		Scan(&m.RuleHealth.SigmaEnabled, &m.RuleHealth.SigmaTotal)
	m.RuleHealth.SigmaDisabled = m.RuleHealth.SigmaTotal - m.RuleHealth.SigmaEnabled
	db.QueryRow(`SELECT COUNT(*) FILTER (WHERE enabled), COUNT(*) FROM yara_rules WHERE tenant_id=$1`, tenantID).
		Scan(&m.RuleHealth.YaraEnabled, &m.RuleHealth.YaraTotal)

	// ── IOC hits ──────────────────────────────────────────────────────────────

	db.QueryRow(fmt.Sprintf(`
		SELECT COUNT(*) FROM alerts
		WHERE (rule_name ILIKE '%%ioc%%' OR rule_name ILIKE '%%indicator%%' OR rule_name ILIKE '%%blocklist%%')
		  AND created_at > now() - INTERVAL '%s'
		  AND tenant_id=$1`, rc.Interval), tenantID).Scan(&m.IOCHits)

	// ── Anomaly score (today vs 7-day daily average) ───────────────────────────

	var todayCount, sevenDayAvg float64
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE created_at > now() - INTERVAL '24 hours' AND tenant_id=$1`, tenantID).Scan(&todayCount)
	db.QueryRow(`
		SELECT COALESCE(AVG(daily_count), 0)
		FROM (
		    SELECT DATE(created_at) AS day, COUNT(*) AS daily_count
		    FROM alerts
		    WHERE created_at BETWEEN now() - INTERVAL '8 days' AND now() - INTERVAL '1 day'
		      AND tenant_id=$1
		    GROUP BY day
		) sub
	`, tenantID).Scan(&sevenDayAvg)

	if sevenDayAvg > 0 {
		m.AnomalyScore = math.Round(todayCount/sevenDayAvg*100) / 100
	}

	// ── Compliance posture (average of latest report scores) ──────────────────

	db.QueryRow(`
		SELECT COALESCE(AVG(CAST(details->>'overall_score' AS NUMERIC)), 0)
		FROM compliance_reports
		WHERE tenant_id=$1
		  AND created_at = (
		      SELECT MAX(created_at) FROM compliance_reports cr2
		      WHERE cr2.framework = compliance_reports.framework AND cr2.tenant_id=$1
		  )
	`, tenantID).Scan(&m.ComplianceScore)

	// ── Threat score ──────────────────────────────────────────────────────────

	var critAlerts, highAlerts, openIncidents, critVulns int
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE severity='critical' AND created_at > now() - INTERVAL '24 hours' AND tenant_id=$1`, tenantID).Scan(&critAlerts)
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE severity='high' AND created_at > now() - INTERVAL '24 hours' AND tenant_id=$1`, tenantID).Scan(&highAlerts)
	db.QueryRow(`SELECT COUNT(*) FROM incidents WHERE status IN ('open','investigating') AND tenant_id=$1`, tenantID).Scan(&openIncidents)
	db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities v JOIN agents a ON a.id=v.agent_id WHERE v.severity='critical' AND a.tenant_id=$1`, tenantID).Scan(&critVulns)

	score := (critAlerts * 5) + (highAlerts * 2) + (openIncidents * 10) + (critVulns * 3)
	if score > 100 {
		score = 100
	}
	m.ThreatScore = score

	// ── Top rules ─────────────────────────────────────────────────────────────

	ruleRows, err := db.Query(fmt.Sprintf(`
		SELECT rule_name, severity, COUNT(*) as cnt
		FROM alerts
		WHERE created_at > now() - INTERVAL '%s' AND tenant_id=$1
		GROUP BY rule_name, severity
		ORDER BY cnt DESC LIMIT 10`, rc.Interval), tenantID)
	if err == nil {
		defer ruleRows.Close()
		for ruleRows.Next() {
			var r RuleCount
			ruleRows.Scan(&r.RuleName, &r.Severity, &r.Count)
			m.TopRules = append(m.TopRules, r)
		}
	}

	// ── Top agents ────────────────────────────────────────────────────────────

	agentRows, err := db.Query(fmt.Sprintf(`
		SELECT a.id, a.hostname, COUNT(al.id) as cnt
		FROM agents a
		JOIN alerts al ON al.agent_id = a.id
		WHERE al.created_at > now() - INTERVAL '%s' AND a.tenant_id=$1
		GROUP BY a.id, a.hostname
		ORDER BY cnt DESC LIMIT 5`, rc.Interval), tenantID)
	if err == nil {
		defer agentRows.Close()
		for agentRows.Next() {
			var aa AgentAlertCount
			agentRows.Scan(&aa.AgentID, &aa.Hostname, &aa.Count)
			m.TopAgents = append(m.TopAgents, aa)
		}
	}

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
	if seconds <= 0 {
		return "N/A"
	}
	d := time.Duration(seconds) * time.Second
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h >= 24 {
		days := h / 24
		hrs := h % 24
		return fmt.Sprintf("%dd %dh", days, hrs)
	}
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}
