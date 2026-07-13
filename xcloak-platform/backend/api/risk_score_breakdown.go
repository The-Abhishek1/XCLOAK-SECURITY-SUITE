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
// tenantID is passed as $2 for defense-in-depth even though agentOwnedBy404
// already verifies ownership at the handler level.
func countQuery(query string, agentID, tenantID int) int {
	var n int
	if err := database.DB.QueryRow(query, agentID, tenantID).Scan(&n); err != nil {
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
	tenantID := tenantIDFromContext(c)

	// Get base risk score
	score, err := repositories.GetRiskScore(fmt.Sprintf("%d", agentID))
	if err != nil {
		c.JSON(404, gin.H{"error": "risk score not found"})
		return
	}

	// Get agent hostname
	var hostname string
	if err := database.DB.QueryRow(`SELECT hostname FROM agents WHERE id=$1 AND tenant_id=$2`, agentID, tenantID).Scan(&hostname); err != nil {
		slog.Warn("risk-breakdown: hostname lookup failed", "agent_id", agentID, "err", err)
	}

	// Build factor breakdown by querying real data
	var factors []RiskFactor

	// Critical alerts
	critAlerts := countQuery(`SELECT COUNT(*) FROM alerts a JOIN agents ag ON ag.id=a.agent_id WHERE a.agent_id=$1 AND ag.tenant_id=$2 AND a.severity='critical'`, agentID, tenantID)
	if critAlerts > 0 {
		factors = append(factors, RiskFactor{
			Label: "Critical Alerts", Points: critAlerts * 20, Count: critAlerts,
			Detail: fmt.Sprintf("%d critical alert(s) × 20 pts", critAlerts),
		})
	}

	// High alerts
	highAlerts := countQuery(`SELECT COUNT(*) FROM alerts a JOIN agents ag ON ag.id=a.agent_id WHERE a.agent_id=$1 AND ag.tenant_id=$2 AND a.severity='high'`, agentID, tenantID)
	if highAlerts > 0 {
		factors = append(factors, RiskFactor{
			Label: "High Alerts", Points: highAlerts * 10, Count: highAlerts,
			Detail: fmt.Sprintf("%d high alert(s) × 10 pts", highAlerts),
		})
	}

	// Medium alerts
	medAlerts := countQuery(`SELECT COUNT(*) FROM alerts a JOIN agents ag ON ag.id=a.agent_id WHERE a.agent_id=$1 AND ag.tenant_id=$2 AND a.severity='medium'`, agentID, tenantID)
	if medAlerts > 0 {
		factors = append(factors, RiskFactor{
			Label: "Medium Alerts", Points: medAlerts * 5, Count: medAlerts,
			Detail: fmt.Sprintf("%d medium alert(s) × 5 pts", medAlerts),
		})
	}

	// IOC matches
	iocMatches := countQuery(`SELECT COUNT(*) FROM alerts a JOIN agents ag ON ag.id=a.agent_id WHERE a.agent_id=$1 AND ag.tenant_id=$2 AND a.rule_name ILIKE '%IOC%'`, agentID, tenantID)
	if iocMatches > 0 {
		factors = append(factors, RiskFactor{
			Label: "IOC Matches", Points: iocMatches * 20, Count: iocMatches,
			Detail: fmt.Sprintf("%d IOC hit(s) × 20 pts — active threat indicators", iocMatches),
		})
	}

	// YARA matches
	yaraMatches := countQuery(`SELECT COUNT(*) FROM alerts a JOIN agents ag ON ag.id=a.agent_id WHERE a.agent_id=$1 AND ag.tenant_id=$2 AND a.rule_name ILIKE '%YARA%'`, agentID, tenantID)
	if yaraMatches > 0 {
		factors = append(factors, RiskFactor{
			Label: "YARA Matches", Points: yaraMatches * 25, Count: yaraMatches,
			Detail: fmt.Sprintf("%d YARA hit(s) × 25 pts — malware signatures matched", yaraMatches),
		})
	}

	// Critical incidents
	critIncidents := countQuery(`SELECT COUNT(*) FROM incidents i JOIN agents ag ON ag.id=i.agent_id WHERE i.agent_id=$1 AND ag.tenant_id=$2 AND i.severity='critical' AND i.status != 'resolved'`, agentID, tenantID)
	if critIncidents > 0 {
		factors = append(factors, RiskFactor{
			Label: "Critical Incidents", Points: critIncidents * 30, Count: critIncidents,
			Detail: fmt.Sprintf("%d open critical incident(s) × 30 pts", critIncidents),
		})
	}

	// Critical vulnerabilities
	critVulns := countQuery(`SELECT COUNT(*) FROM vulnerabilities v JOIN agents ag ON ag.id=v.agent_id WHERE v.agent_id=$1 AND ag.tenant_id=$2 AND v.severity='critical'`, agentID, tenantID)
	if critVulns > 0 {
		factors = append(factors, RiskFactor{
			Label: "Critical CVEs", Points: critVulns * 5, Count: critVulns,
			Detail: fmt.Sprintf("%d critical CVE(s) × 5 pts", critVulns),
		})
	}

	// FIM violations
	fimViolations := countQuery(`SELECT COUNT(*) FROM fim_alerts fa JOIN agents ag ON ag.id=fa.agent_id WHERE fa.agent_id=$1 AND ag.tenant_id=$2 AND fa.created_at > now() - INTERVAL '7 days'`, agentID, tenantID)
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
