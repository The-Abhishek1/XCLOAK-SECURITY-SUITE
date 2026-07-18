package api

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/services"
)

// GetAgentCISFindings returns the full CIS benchmark result set for one agent.
// GET /api/cis/agents/:id
func GetAgentCISFindings(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	agentID, err := strconv.Atoi(c.Param("id"))
	if err != nil || agentID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent id"})
		return
	}
	if !agentBelongsToTenant(agentID, tenantID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	rows, err := database.RDB().Query(`
		SELECT control_id, platform, profile, category, title,
		       status, severity, description, evidence, remediation, checked_at
		FROM cis_findings
		WHERE agent_id = $1
		ORDER BY
			CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
			              WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
			category, control_id
	`, agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	type row struct {
		ControlID   string    `json:"control_id"`
		Platform    string    `json:"platform"`
		Profile     string    `json:"profile"`
		Category    string    `json:"category"`
		Title       string    `json:"title"`
		Status      string    `json:"status"`
		Severity    string    `json:"severity"`
		Description string    `json:"description"`
		Evidence    string    `json:"evidence"`
		Remediation string    `json:"remediation"`
		CheckedAt   time.Time `json:"checked_at"`
	}
	findings := []row{}
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.ControlID, &r.Platform, &r.Profile, &r.Category,
			&r.Title, &r.Status, &r.Severity, &r.Description,
			&r.Evidence, &r.Remediation, &r.CheckedAt); err != nil {
			continue
		}
		findings = append(findings, r)
	}
	if findings == nil {
		findings = []row{}
	}

	pass, total, score := services.AgentCISScore(agentID)
	c.JSON(http.StatusOK, gin.H{
		"agent_id": agentID,
		"score":    score,
		"pass":     pass,
		"total":    total,
		"findings": findings,
	})
}

// GetCISSummary returns per-control pass/fail/warn counts across the fleet.
// GET /api/cis/summary
func GetCISSummary(c *gin.Context) {
	tenantID := tenantIDFromContext(c)

	type controlRow struct {
		ControlID string `json:"control_id"`
		Title     string `json:"title"`
		Category  string `json:"category"`
		Platform  string `json:"platform"`
		Severity  string `json:"severity"`
		Pass      int    `json:"pass"`
		Fail      int    `json:"fail"`
		Warn      int    `json:"warn"`
		Unknown   int    `json:"unknown"`
		Total     int    `json:"total"`
	}

	rows, err := database.RDB().Query(`
		SELECT
			control_id,
			MAX(title)    AS title,
			MAX(category) AS category,
			MAX(platform) AS platform,
			MAX(severity) AS severity,
			COUNT(*) FILTER (WHERE status = 'pass')    AS pass,
			COUNT(*) FILTER (WHERE status = 'fail')    AS fail,
			COUNT(*) FILTER (WHERE status = 'warn')    AS warn,
			COUNT(*) FILTER (WHERE status = 'unknown') AS unknown,
			COUNT(*)                                   AS total
		FROM cis_findings
		WHERE tenant_id = $1
		GROUP BY control_id
		ORDER BY
			CASE MAX(severity) WHEN 'critical' THEN 1 WHEN 'high' THEN 2
			                   WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
			control_id
	`, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	controls := []controlRow{}
	for rows.Next() {
		var r controlRow
		if err := rows.Scan(&r.ControlID, &r.Title, &r.Category, &r.Platform, &r.Severity,
			&r.Pass, &r.Fail, &r.Warn, &r.Unknown, &r.Total); err != nil {
			continue
		}
		controls = append(controls, r)
	}
	if controls == nil {
		controls = []controlRow{}
	}

	// Fleet-level score: across all agents and all controls.
	var totalPass, totalAll int
	database.RDB().QueryRow(`
		SELECT
			COUNT(*) FILTER (WHERE status = 'pass'),
			COUNT(*)
		FROM cis_findings
		WHERE tenant_id = $1
	`, tenantID).Scan(&totalPass, &totalAll)

	fleetScore := 0.0
	if totalAll > 0 {
		fleetScore = float64(totalPass) / float64(totalAll) * 100
	}

	c.JSON(http.StatusOK, gin.H{
		"fleet_score": fleetScore,
		"total_pass":  totalPass,
		"total":       totalAll,
		"controls":    controls,
	})
}

// GetAgentCISScore returns just the score for one agent — lightweight call for
// dashboard widgets.
// GET /api/cis/agents/:id/score
func GetAgentCISScore(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	agentID, err := strconv.Atoi(c.Param("id"))
	if err != nil || agentID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent id"})
		return
	}
	if !agentBelongsToTenant(agentID, tenantID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	pass, total, score := services.AgentCISScore(agentID)

	var checkedAt sql.NullTime
	database.RDB().QueryRow(
		`SELECT MAX(checked_at) FROM cis_findings WHERE agent_id = $1`, agentID,
	).Scan(&checkedAt)

	c.JSON(http.StatusOK, gin.H{
		"agent_id":   agentID,
		"score":      score,
		"pass":       pass,
		"total":      total,
		"checked_at": checkedAt.Time,
	})
}

// TriggerCISScan runs the benchmark scanner for one agent on demand.
// POST /api/cis/agents/:id/scan
func TriggerCISScan(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	agentID, err := strconv.Atoi(c.Param("id"))
	if err != nil || agentID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent id"})
		return
	}
	if !agentBelongsToTenant(agentID, tenantID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	go func() {
		if err := services.RunCISBenchmark(agentID, tenantID); err != nil {
			// Non-fatal — caller gets 202 regardless
			_ = err
		}
	}()

	c.JSON(http.StatusAccepted, gin.H{"message": "CIS scan started", "agent_id": agentID})
}
