package api

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

type DeepDiveReport struct {
	IncidentID    int                    `json:"incident_id"`
	Title         string                 `json:"title"`
	Severity      string                 `json:"severity"`
	GeneratedAt   time.Time              `json:"generated_at"`
	Timeline      []DeepDiveEvent        `json:"timeline"`
	AffectedAsset DeepDiveAsset          `json:"affected_asset"`
	Indicators    []DeepDiveIndicator    `json:"indicators"`
	AISummary     string                 `json:"ai_summary"`
	Recommendations []string             `json:"recommendations"`
	MITRECoverage []string               `json:"mitre_coverage"`
}

type DeepDiveEvent struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`  // alert, note, status_change, task
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Severity  string `json:"severity,omitempty"`
}

type DeepDiveAsset struct {
	AgentID   int    `json:"agent_id"`
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ip_address"`
	OS        string `json:"os"`
	Status    string `json:"status"`
	RiskLevel string `json:"risk_level"`
}

type DeepDiveIndicator struct {
	Type      string `json:"type"`   // ip, domain, hash, process, file
	Value     string `json:"value"`
	Context   string `json:"context"`
}

// GetIncidentDeepDive — GET /api/incidents/:id/deepdive
// Assembles a full structured report from all available data sources.
func GetIncidentDeepDive(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid incident id"})
		return
	}

	incident, err := repositories.GetIncidentByID(idStr, tenantIDFromContext(c))
	if err != nil {
		c.JSON(404, gin.H{"error": "incident not found"})
		return
	}

	report := DeepDiveReport{
		IncidentID:  id,
		Title:       incident.Title,
		Severity:    incident.Severity,
		GeneratedAt: time.Now(),
	}

	// ── Affected asset ────────────────────────────────────────
	var hostname, ipAddr, os, status string
	database.DB.QueryRow(
		`SELECT hostname, ip_address, os, status FROM agents WHERE id=$1`, incident.AgentID,
	).Scan(&hostname, &ipAddr, &os, &status)

	var riskLevel string
	database.DB.QueryRow(
		`SELECT risk_level FROM asset_risk_scores WHERE agent_id=$1`, incident.AgentID,
	).Scan(&riskLevel)

	report.AffectedAsset = DeepDiveAsset{
		AgentID:   incident.AgentID,
		Hostname:  hostname,
		IPAddress: ipAddr,
		OS:        os,
		Status:    status,
		RiskLevel: riskLevel,
	}

	// ── Timeline: alerts ──────────────────────────────────────
	alertRows, _ := database.DB.Query(`
		SELECT rule_name, severity, log_message, mitre_technique, created_at
		FROM alerts WHERE agent_id=$1
		ORDER BY created_at
		LIMIT 30
	`, incident.AgentID)
	if alertRows != nil {
		defer alertRows.Close()
		for alertRows.Next() {
			var ruleName, sev, logMsg, mitre, ts string
			if alertRows.Scan(&ruleName, &sev, &logMsg, &mitre, &ts) == nil {
				report.Timeline = append(report.Timeline, DeepDiveEvent{
					Timestamp: ts,
					Type:      "alert",
					Title:     ruleName,
					Detail:    logMsg,
					Severity:  sev,
				})
				if mitre != "" {
					report.MITRECoverage = appendUnique(report.MITRECoverage, mitre)
				}
			}
		}
	}

	// ── Timeline: incident events (notes, status changes) ─────
	events, _ := repositories.GetIncidentEvents(idStr)
	for _, ev := range events {
		report.Timeline = append(report.Timeline, DeepDiveEvent{
			Timestamp: ev.CreatedAt.Format(time.RFC3339),
			Type:      ev.EventType,
			Title:     ev.EventType,
			Detail:    ev.Details,
		})
	}

	// ── Indicators from recent connections ────────────────────
	connRows, _ := database.DB.Query(`
		SELECT remote_address, state, protocol FROM endpoint_connections
		WHERE agent_id=$1 AND state='ESTABLISHED'
		  AND remote_address NOT LIKE '127.%'
		  AND remote_address NOT LIKE '::1%'
		ORDER BY id DESC LIMIT 20
	`, incident.AgentID)
	if connRows != nil {
		defer connRows.Close()
		seen := map[string]bool{}
		for connRows.Next() {
			var remote, state, proto string
			if connRows.Scan(&remote, &state, &proto) == nil {
				ip := remote
				if idx := strings.LastIndex(ip, ":"); idx > 0 {
					ip = ip[:idx]
				}
				if !seen[ip] {
					seen[ip] = true
					report.Indicators = append(report.Indicators, DeepDiveIndicator{
						Type:    "ip",
						Value:   ip,
						Context: fmt.Sprintf("%s connection via %s", state, proto),
					})
				}
			}
		}
	}

	// ── Indicators from processes at incident time ────────────
	procRows, _ := database.DB.Query(`
		SELECT name, pid FROM endpoint_processes
		WHERE agent_id=$1 ORDER BY id DESC LIMIT 5
	`, incident.AgentID)
	if procRows != nil {
		defer procRows.Close()
		for procRows.Next() {
			var name string
			var pid int
			if procRows.Scan(&name, &pid) == nil {
				report.Indicators = append(report.Indicators, DeepDiveIndicator{
					Type:    "process",
					Value:   fmt.Sprintf("%s (PID %d)", name, pid),
					Context: "running at time of incident",
				})
			}
		}
	}

	// ── YARA matches on this agent ────────────────────────────
	yaraRows, _ := database.DB.Query(`
		SELECT rule_name, file_path FROM yara_matches
		WHERE agent_id=$1 ORDER BY matched_at DESC LIMIT 5
	`, incident.AgentID)
	if yaraRows != nil {
		defer yaraRows.Close()
		for yaraRows.Next() {
			var ruleName, filePath string
			if yaraRows.Scan(&ruleName, &filePath) == nil {
				report.Indicators = append(report.Indicators, DeepDiveIndicator{
					Type:    "file",
					Value:   filePath,
					Context: "YARA match: " + ruleName,
				})
			}
		}
	}

	// ── AI summary ────────────────────────────────────────────
	var aiSummary string
	database.DB.QueryRow(
		`SELECT COALESCE(ai_summary,'') FROM incidents WHERE id=$1`, id,
	).Scan(&aiSummary)

	if aiSummary == "" {
		// Generate on demand
		summary, llmErr := services.SummarizeIncident(id, tenantIDFromContext(c))
		if llmErr == nil && summary != nil {
			aiSummary = summary.Summary
			report.Recommendations = summary.RecommendedSteps
		}
	}
	report.AISummary = aiSummary

	if report.Recommendations == nil {
		report.Recommendations = defaultRecommendations(incident.Severity)
	}
	if report.Timeline == nil {
		report.Timeline = []DeepDiveEvent{}
	}
	if report.Indicators == nil {
		report.Indicators = []DeepDiveIndicator{}
	}

	c.JSON(200, report)
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

func defaultRecommendations(severity string) []string {
	base := []string{
		"Collect full process and connection snapshot from affected agent",
		"Review authentication logs for anomalous login patterns",
		"Check for lateral movement to other agents",
		"Verify firewall rules block the implicated IPs",
	}
	if severity == "critical" {
		return append([]string{
			"IMMEDIATE: Consider isolating the host via SOAR → isolate_host",
			"IMMEDIATE: Preserve memory and disk artifacts before remediation",
		}, base...)
	}
	return base
}
