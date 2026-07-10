package api

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/repositories"
)

type RiskFactor struct {
	Label  string `json:"label"`
	Points int    `json:"points"`
	Count  int    `json:"count"`
	Detail string `json:"detail"`
}

type RiskBreakdown struct {
	AgentID   int          `json:"agent_id"`
	Hostname  string       `json:"hostname"`
	Score     int          `json:"score"`
	Level     string       `json:"level"`
	Factors   []RiskFactor `json:"factors"`
	UpdatedAt string       `json:"updated_at"`
}

// countQuery runs a single-value COUNT query and logs (rather than
// silently swallows) a failure, returning 0 so a transient DB error
// degrades to "no factor" instead of panicking or corrupting the response.
func countQuery(query string, agentID int) int {
	var n int
	if err := database.DB.QueryRow(query, agentID).Scan(&n); err != nil {
		slog.Error("risk-breakdown: count query failed", "agent_id", agentID, "err", err)
		return 0
	}
	return n
}

// GetAgentRiskBreakdown — GET /api/agents/:id/risk/breakdown
func GetAgentRiskBreakdown(c *gin.Context) {
	agentID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid agent id"})
		return
	}
	if !agentOwnedBy404(c, c.Param("id")) {
		return
	}

	// Get base risk score
	score, err := repositories.GetRiskScore(fmt.Sprintf("%d", agentID))
	if err != nil {
		c.JSON(404, gin.H{"error": "risk score not found"})
		return
	}

	// Get agent hostname
	var hostname string
	if err := database.DB.QueryRow(`SELECT hostname FROM agents WHERE id=$1`, agentID).Scan(&hostname); err != nil {
		slog.Warn("risk-breakdown: hostname lookup failed", "agent_id", agentID, "err", err)
	}

	// Build factor breakdown by querying real data
	var factors []RiskFactor

	// Critical alerts
	critAlerts := countQuery(`SELECT COUNT(*) FROM alerts WHERE agent_id=$1 AND severity='critical'`, agentID)
	if critAlerts > 0 {
		factors = append(factors, RiskFactor{
			Label: "Critical Alerts", Points: critAlerts * 20, Count: critAlerts,
			Detail: fmt.Sprintf("%d critical alert(s) × 20 pts", critAlerts),
		})
	}

	// High alerts
	highAlerts := countQuery(`SELECT COUNT(*) FROM alerts WHERE agent_id=$1 AND severity='high'`, agentID)
	if highAlerts > 0 {
		factors = append(factors, RiskFactor{
			Label: "High Alerts", Points: highAlerts * 10, Count: highAlerts,
			Detail: fmt.Sprintf("%d high alert(s) × 10 pts", highAlerts),
		})
	}

	// Medium alerts
	medAlerts := countQuery(`SELECT COUNT(*) FROM alerts WHERE agent_id=$1 AND severity='medium'`, agentID)
	if medAlerts > 0 {
		factors = append(factors, RiskFactor{
			Label: "Medium Alerts", Points: medAlerts * 5, Count: medAlerts,
			Detail: fmt.Sprintf("%d medium alert(s) × 5 pts", medAlerts),
		})
	}

	// IOC matches
	iocMatches := countQuery(`SELECT COUNT(*) FROM alerts WHERE agent_id=$1 AND rule_name ILIKE '%IOC%'`, agentID)
	if iocMatches > 0 {
		factors = append(factors, RiskFactor{
			Label: "IOC Matches", Points: iocMatches * 20, Count: iocMatches,
			Detail: fmt.Sprintf("%d IOC hit(s) × 20 pts — active threat indicators", iocMatches),
		})
	}

	// YARA matches
	yaraMatches := countQuery(`SELECT COUNT(*) FROM alerts WHERE agent_id=$1 AND rule_name ILIKE '%YARA%'`, agentID)
	if yaraMatches > 0 {
		factors = append(factors, RiskFactor{
			Label: "YARA Matches", Points: yaraMatches * 25, Count: yaraMatches,
			Detail: fmt.Sprintf("%d YARA hit(s) × 25 pts — malware signatures matched", yaraMatches),
		})
	}

	// Critical incidents
	critIncidents := countQuery(`SELECT COUNT(*) FROM incidents WHERE agent_id=$1 AND severity='critical' AND status != 'resolved'`, agentID)
	if critIncidents > 0 {
		factors = append(factors, RiskFactor{
			Label: "Critical Incidents", Points: critIncidents * 30, Count: critIncidents,
			Detail: fmt.Sprintf("%d open critical incident(s) × 30 pts", critIncidents),
		})
	}

	// Critical vulnerabilities
	critVulns := countQuery(`SELECT COUNT(*) FROM vulnerabilities WHERE agent_id=$1 AND severity='critical'`, agentID)
	if critVulns > 0 {
		factors = append(factors, RiskFactor{
			Label: "Critical CVEs", Points: critVulns * 5, Count: critVulns,
			Detail: fmt.Sprintf("%d critical CVE(s) × 5 pts", critVulns),
		})
	}

	// FIM violations
	fimViolations := countQuery(`SELECT COUNT(*) FROM fim_alerts WHERE agent_id=$1 AND created_at > now() - INTERVAL '7 days'`, agentID)
	if fimViolations > 0 {
		factors = append(factors, RiskFactor{
			Label: "FIM Violations", Points: fimViolations * 8, Count: fimViolations,
			Detail: fmt.Sprintf("%d file integrity violation(s) in last 7 days × 8 pts", fimViolations),
		})
	}

	if factors == nil {
		factors = []RiskFactor{}
	}

	c.JSON(200, RiskBreakdown{
		AgentID:   agentID,
		Hostname:  hostname,
		Score:     score.RiskScore,
		Level:     score.RiskLevel,
		Factors:   factors,
		UpdatedAt: score.UpdatedAt.Format("2006-01-02 15:04 UTC"),
	})
}
