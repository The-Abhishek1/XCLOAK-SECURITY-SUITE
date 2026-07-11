package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
)

// GetDPIFindings returns paginated DPI findings for the authenticated tenant.
// Query params: agent_id, finding_type, severity, alert_only, limit, offset
func GetDPIFindings(c *gin.Context) {
	tenantID := tenantIDFromContext(c)

	limit := 100
	offset := 0
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 && l <= 500 {
		limit = l
	}
	if o, err := strconv.Atoi(c.Query("offset")); err == nil && o >= 0 {
		offset = o
	}

	where := "tenant_id = $1"
	args := []interface{}{tenantID}
	pIdx := 2

	if v := c.Query("agent_id"); v != "" {
		where += " AND agent_id = $" + strconv.Itoa(pIdx)
		args = append(args, v)
		pIdx++
	}
	if v := c.Query("finding_type"); v != "" {
		where += " AND finding_type = $" + strconv.Itoa(pIdx)
		args = append(args, v)
		pIdx++
	}
	if v := c.Query("severity"); v != "" {
		where += " AND severity = $" + strconv.Itoa(pIdx)
		args = append(args, v)
		pIdx++
	}
	if c.Query("alert_only") == "true" {
		where += " AND alert_fired = true"
	}

	args = append(args, limit, offset)

	rows, err := database.DB.Query(`
		SELECT id, agent_id, finding_type, severity, score,
		       indicator, description, mitre_technique,
		       raw_context, alert_fired, detected_at
		FROM dpi_findings
		WHERE `+where+`
		ORDER BY detected_at DESC
		LIMIT $`+strconv.Itoa(pIdx)+` OFFSET $`+strconv.Itoa(pIdx+1),
		args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type DPIFinding struct {
		ID             int    `json:"id"`
		AgentID        int    `json:"agent_id"`
		FindingType    string `json:"finding_type"`
		Severity       string `json:"severity"`
		Score          int    `json:"score"`
		Indicator      string `json:"indicator"`
		Description    string `json:"description"`
		MitreTechnique string `json:"mitre_technique"`
		RawContext     []byte `json:"raw_context"`
		AlertFired     bool   `json:"alert_fired"`
		DetectedAt     string `json:"detected_at"`
	}

	var findings []DPIFinding
	for rows.Next() {
		var f DPIFinding
		if rows.Scan(&f.ID, &f.AgentID, &f.FindingType, &f.Severity, &f.Score,
			&f.Indicator, &f.Description, &f.MitreTechnique,
			&f.RawContext, &f.AlertFired, &f.DetectedAt) == nil {
			findings = append(findings, f)
		}
	}
	if findings == nil {
		findings = []DPIFinding{}
	}

	c.JSON(http.StatusOK, gin.H{"findings": findings})
}

// GetDPIFindingsSummary returns 24-hour aggregate stats by finding type and severity.
func GetDPIFindingsSummary(c *gin.Context) {
	tenantID := tenantIDFromContext(c)

	type TypeCount struct {
		FindingType string `json:"finding_type"`
		Severity    string `json:"severity"`
		Count       int    `json:"count"`
	}

	rows, err := database.DB.Query(`
		SELECT finding_type, severity, COUNT(*) AS cnt
		FROM dpi_findings
		WHERE tenant_id = $1
		  AND detected_at > NOW() - INTERVAL '24 hours'
		GROUP BY finding_type, severity
		ORDER BY cnt DESC
	`, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var breakdown []TypeCount
	for rows.Next() {
		var tc TypeCount
		if rows.Scan(&tc.FindingType, &tc.Severity, &tc.Count) == nil {
			breakdown = append(breakdown, tc)
		}
	}
	if breakdown == nil {
		breakdown = []TypeCount{}
	}

	var total, alerted int
	database.DB.QueryRow(`
		SELECT COUNT(*), SUM(CASE WHEN alert_fired THEN 1 ELSE 0 END)
		FROM dpi_findings
		WHERE tenant_id=$1 AND detected_at > NOW() - INTERVAL '24 hours'
	`, tenantID).Scan(&total, &alerted)

	c.JSON(http.StatusOK, gin.H{
		"total_24h":   total,
		"alerted_24h": alerted,
		"breakdown":   breakdown,
	})
}
