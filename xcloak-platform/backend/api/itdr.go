package api

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// ListITDRFindings returns open ITDR findings for the tenant, optionally
// filtered by severity and finding_type.
// GET /api/itdr/findings
func ListITDRFindings(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	status := c.DefaultQuery("status", "open")
	severity := c.Query("severity")
	findingType := c.Query("type")
	limitStr := c.DefaultQuery("limit", "100")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	query := `
		SELECT id, tenant_id, finding_type, severity, identity, identity_type,
		       COALESCE(source_ip,''), description, evidence,
		       COALESCE(mitre_technique,''), status,
		       agent_id, created_at, updated_at, resolved_at, dedup_key
		FROM itdr_findings
		WHERE tenant_id = $1 AND status = $2`
	args := []any{tenantID, status}

	if severity != "" {
		args = append(args, severity)
		query += ` AND severity = $` + strconv.Itoa(len(args))
	}
	if findingType != "" {
		args = append(args, findingType)
		query += ` AND finding_type = $` + strconv.Itoa(len(args))
	}
	query += ` ORDER BY created_at DESC LIMIT $` + strconv.Itoa(len(args)+1)
	args = append(args, limit)

	rows, err := database.RDB().Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	var findings []models.ITDRFinding
	for rows.Next() {
		var f models.ITDRFinding
		var agentID sql.NullInt64
		var resolvedAt sql.NullTime
		var evidenceRaw []byte
		if err := rows.Scan(
			&f.ID, &f.TenantID, &f.FindingType, &f.Severity,
			&f.Identity, &f.IdentityType, &f.SourceIP, &f.Description,
			&evidenceRaw, &f.MITRETechnique, &f.Status,
			&agentID, &f.CreatedAt, &f.UpdatedAt, &resolvedAt, &f.DedupKey,
		); err != nil {
			continue
		}
		f.Evidence = string(evidenceRaw)
		if agentID.Valid {
			id := int(agentID.Int64)
			f.AgentID = &id
		}
		if resolvedAt.Valid {
			f.ResolvedAt = &resolvedAt.Time
		}
		findings = append(findings, f)
	}
	if findings == nil {
		findings = []models.ITDRFinding{}
	}
	c.JSON(http.StatusOK, findings)
}

// GetITDRFinding returns a single ITDR finding by ID.
// GET /api/itdr/findings/:id
func GetITDRFinding(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	findingID, err := strconv.Atoi(c.Param("id"))
	if err != nil || findingID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var f models.ITDRFinding
	var agentID sql.NullInt64
	var resolvedAt sql.NullTime
	var evidenceRaw []byte

	err = database.RDB().QueryRow(`
		SELECT id, tenant_id, finding_type, severity, identity, identity_type,
		       COALESCE(source_ip,''), description, evidence,
		       COALESCE(mitre_technique,''), status,
		       agent_id, created_at, updated_at, resolved_at, dedup_key
		FROM itdr_findings
		WHERE id = $1 AND tenant_id = $2
	`, findingID, tenantID).Scan(
		&f.ID, &f.TenantID, &f.FindingType, &f.Severity,
		&f.Identity, &f.IdentityType, &f.SourceIP, &f.Description,
		&evidenceRaw, &f.MITRETechnique, &f.Status,
		&agentID, &f.CreatedAt, &f.UpdatedAt, &resolvedAt, &f.DedupKey,
	)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	f.Evidence = string(evidenceRaw)
	if agentID.Valid {
		id := int(agentID.Int64)
		f.AgentID = &id
	}
	if resolvedAt.Valid {
		f.ResolvedAt = &resolvedAt.Time
	}
	c.JSON(http.StatusOK, f)
}

// UpdateITDRFindingStatus acknowledges, resolves, or marks a finding as a
// false positive.
// PATCH /api/itdr/findings/:id/status
func UpdateITDRFindingStatus(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	findingID, err := strconv.Atoi(c.Param("id"))
	if err != nil || findingID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var body struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	validStatuses := map[string]bool{
		"open": true, "acknowledged": true,
		"resolved": true, "false_positive": true,
	}
	if !validStatuses[body.Status] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status"})
		return
	}

	var resolvedAt *time.Time
	if body.Status == "resolved" || body.Status == "false_positive" {
		t := time.Now()
		resolvedAt = &t
	}

	res, err := database.DB.Exec(`
		UPDATE itdr_findings
		SET status = $1, updated_at = NOW(), resolved_at = $2
		WHERE id = $3 AND tenant_id = $4
	`, body.Status, resolvedAt, findingID, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": body.Status})
}

// GetITDRSummary returns a count of open findings grouped by severity and type.
// GET /api/itdr/summary
func GetITDRSummary(c *gin.Context) {
	tenantID := tenantIDFromContext(c)

	type row struct {
		FindingType string `json:"finding_type"`
		Severity    string `json:"severity"`
		Count       int    `json:"count"`
	}

	rows, err := database.RDB().Query(`
		SELECT finding_type, severity, COUNT(*) AS count
		FROM itdr_findings
		WHERE tenant_id = $1 AND status = 'open'
		GROUP BY finding_type, severity
		ORDER BY
			CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
			              WHEN 'medium' THEN 3 ELSE 4 END,
			finding_type
	`, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	defer rows.Close()

	var summary []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.FindingType, &r.Severity, &r.Count); err != nil {
			continue
		}
		summary = append(summary, r)
	}
	if summary == nil {
		summary = []row{}
	}
	c.JSON(http.StatusOK, gin.H{"findings": summary})
}
