package api

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// UpdateIncidentStatus — PUT /api/incidents/:id/status
// Body: { "status": "open" | "investigating" | "resolved" | "closed" }
func UpdateIncidentStatus(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid incident id"})
		return
	}

	// Verify the incident belongs to the caller's tenant before mutating it.
	if _, err := repositories.GetIncidentByID(c.Param("id"), tenantIDFromContext(c)); err != nil {
		c.JSON(404, gin.H{"error": "incident not found"})
		return
	}

	var body struct {
		Status string `json:"status"`
	}

	if err := c.ShouldBindJSON(&body); err != nil || body.Status == "" {
		c.JSON(400, gin.H{"error": "status is required"})
		return
	}

	valid := map[string]bool{"open": true, "investigating": true, "resolved": true, "closed": true}
	if !valid[body.Status] {
		c.JSON(400, gin.H{"error": "status must be: open, investigating, resolved, or closed"})
		return
	}

	if err := services.UpdateIncidentStatus(id, body.Status, tenantIDFromContext(c)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Record MTTR when incident is resolved or closed.
	if body.Status == "resolved" || body.Status == "closed" {
		services.RecordMTTR(id)
	}

	username, _ := c.Get("username")
	services.LogEvent("UPDATE_INCIDENT_STATUS",
		"incident "+strconv.Itoa(id)+" → "+body.Status,
		username.(string),
	)

	c.JSON(200, gin.H{"message": "Status updated", "status": body.Status})
}

// AddIncidentNote — POST /api/incidents/:id/notes
// Body: { "note": "..." }
func AddIncidentNote(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid incident id"})
		return
	}

	// Verify the incident belongs to the caller's tenant before mutating it.
	if _, err := repositories.GetIncidentByID(c.Param("id"), tenantIDFromContext(c)); err != nil {
		c.JSON(404, gin.H{"error": "incident not found"})
		return
	}

	var body struct {
		Note string `json:"note"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Note == "" {
		c.JSON(400, gin.H{"error": "note is required"})
		return
	}

	username, _ := c.Get("username")
	user := "admin"
	if username != nil {
		user = username.(string)
	}

	if err := services.AddIncidentEvent(id, "note", body.Note, user, tenantIDFromContext(c)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "Note added"})
}

// GetIncidentAlerts — GET /api/incidents/:id/alerts
// Returns alerts that were linked to the incident via alert clustering.
func GetIncidentAlerts(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid incident id"})
		return
	}
	tenantID := tenantIDFromContext(c)

	if _, err := repositories.GetIncidentByID(fmt.Sprintf("%d", id), tenantID); err != nil {
		c.JSON(404, gin.H{"error": "incident not found"})
		return
	}

	type linkedAlert struct {
		ID        int       `json:"id"`
		AgentID   int       `json:"agent_id"`
		Severity  string    `json:"severity"`
		RuleName  string    `json:"rule_name"`
		CreatedAt time.Time `json:"created_at"`
	}

	rows, err := database.DB.Query(`
		SELECT a.id, a.agent_id, a.severity, a.rule_name, a.created_at
		FROM alerts a
		JOIN alert_cluster_members acm ON acm.alert_id = a.id
		JOIN alert_clusters ac ON ac.id = acm.cluster_id
		WHERE ac.auto_incident_id = $1 AND a.tenant_id = $2
		ORDER BY a.created_at DESC
		LIMIT 50
	`, id, tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	alerts := []linkedAlert{}
	for rows.Next() {
		var a linkedAlert
		if err := rows.Scan(&a.ID, &a.AgentID, &a.Severity, &a.RuleName, &a.CreatedAt); err == nil {
			alerts = append(alerts, a)
		}
	}
	if alerts == nil {
		alerts = []linkedAlert{}
	}
	c.JSON(200, alerts)
}

// UpdateIncidentSeverity — PATCH /api/incidents/:id/severity
// Body: { "severity": "low" | "medium" | "high" | "critical" }
func UpdateIncidentSeverity(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid incident id"})
		return
	}
	tenantID := tenantIDFromContext(c)

	if _, err := repositories.GetIncidentByID(fmt.Sprintf("%d", id), tenantID); err != nil {
		c.JSON(404, gin.H{"error": "incident not found"})
		return
	}

	var body struct {
		Severity string `json:"severity"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Severity == "" {
		c.JSON(400, gin.H{"error": "severity is required"})
		return
	}

	valid := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	if !valid[body.Severity] {
		c.JSON(400, gin.H{"error": "severity must be: low, medium, high, or critical"})
		return
	}

	res, err := database.DB.Exec(
		`UPDATE incidents SET severity = $1 WHERE id = $2 AND tenant_id = $3`,
		body.Severity, id, tenantID,
	)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		c.JSON(404, gin.H{"error": "incident not found"})
		return
	}

	c.JSON(200, gin.H{"severity": body.Severity})
}
