package api

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/services"
)

// AcknowledgeAlert — POST /api/alerts/:id/acknowledge
// Marks an alert as acknowledged by the current user with an optional note.
func AcknowledgeAlert(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid alert id"})
		return
	}

	var body struct {
		Note string `json:"note"`
	}
	c.ShouldBindJSON(&body)

	username, _ := c.Get("username")
	user := fmt.Sprintf("%v", username)
	now := time.Now()

	tag, err := database.DB.Exec(`
		UPDATE alerts
		SET status = 'acknowledged',
		    acknowledged_by = $1,
		    acknowledged_at = $2,
		    note = CASE WHEN $3 = '' THEN note ELSE $3 END
		WHERE id = $4 AND tenant_id = $5
	`, user, now, body.Note, id, tenantIDFromContext(c))

	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		c.JSON(404, gin.H{"error": "alert not found"})
		return
	}

	services.LogEvent("ALERT_ACK",
		fmt.Sprintf("Alert #%d acknowledged by %s: %s", id, user, body.Note),
		user)

	c.JSON(200, gin.H{
		"message":         "alert acknowledged",
		"acknowledged_by": user,
		"acknowledged_at": now,
	})
}

// ResolveAlert — POST /api/alerts/:id/resolve
func ResolveAlert(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid alert id"})
		return
	}

	var body struct {
		Note string `json:"note"`
	}
	c.ShouldBindJSON(&body)

	username, _ := c.Get("username")
	user := fmt.Sprintf("%v", username)

	tag, err := database.DB.Exec(`
		UPDATE alerts
		SET status = 'resolved',
		    acknowledged_by = $1,
		    acknowledged_at = NOW(),
		    note = CASE WHEN $2 = '' THEN note ELSE $2 END
		WHERE id = $3 AND tenant_id = $4
	`, user, body.Note, id, tenantIDFromContext(c))

	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		c.JSON(404, gin.H{"error": "alert not found"})
		return
	}

	services.LogEvent("ALERT_RESOLVE",
		fmt.Sprintf("Alert #%d resolved by %s", id, user), user)

	c.JSON(200, gin.H{"message": "alert resolved"})
}

// BulkAcknowledgeAlerts — POST /api/alerts/bulk-acknowledge
func BulkAcknowledgeAlerts(c *gin.Context) {
	var body struct {
		IDs  []int  `json:"ids"`
		Note string `json:"note"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.IDs) == 0 {
		c.JSON(400, gin.H{"error": "ids required"})
		return
	}

	username, _ := c.Get("username")
	user := fmt.Sprintf("%v", username)

	// Build $1,$2,... placeholder
	args := []interface{}{user, time.Now(), body.Note, tenantIDFromContext(c)}
	placeholders := ""
	for i, id := range body.IDs {
		if i > 0 {
			placeholders += ","
		}
		args = append(args, id)
		placeholders += fmt.Sprintf("$%d", len(args))
	}

	_, err := database.DB.Exec(fmt.Sprintf(`
		UPDATE alerts
		SET status = 'acknowledged',
		    acknowledged_by = $1,
		    acknowledged_at = $2,
		    note = CASE WHEN $3 = '' THEN note ELSE $3 END
		WHERE id IN (%s) AND status = 'open' AND tenant_id = $4
	`, placeholders), args...)

	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	services.LogEvent("BULK_ACK",
		fmt.Sprintf("%d alerts bulk-acknowledged by %s", len(body.IDs), user), user)

	c.JSON(200, gin.H{"acknowledged": len(body.IDs)})
}

// GetAlertsPaginated — GET /api/alerts/paginated
// Query: page, per_page, severity, status, agent_id, q
func GetAlertsPaginated(c *gin.Context) {
	page, _    := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	severity   := c.Query("severity")
	status     := c.Query("status")  // open | acknowledged | resolved | all
	agentID    := c.Query("agent_id")
	q          := c.Query("q")

	if page < 1    { page = 1 }
	if perPage > 200 { perPage = 200 }

	where := "WHERE alerts.tenant_id=$1"
	args  := []interface{}{tenantIDFromContext(c)}
	idx   := 2

	if severity != "" && severity != "all" {
		where += fmt.Sprintf(" AND alerts.severity=$%d", idx)
		args = append(args, severity); idx++
	}
	if status != "" && status != "all" {
		where += fmt.Sprintf(" AND alerts.status=$%d", idx)
		args = append(args, status); idx++
	} else if status == "" {
		where += " AND alerts.status='open'"
	}
	if agentID != "" {
		where += fmt.Sprintf(" AND alerts.agent_id=$%d", idx)
		args = append(args, agentID); idx++
	}
	if q != "" {
		where += fmt.Sprintf(" AND (alerts.rule_name ILIKE $%d OR alerts.log_message ILIKE $%d OR alerts.mitre_technique ILIKE $%d)", idx, idx, idx)
		args = append(args, "%"+q+"%"); idx++
	}

	var total int
	database.DB.QueryRow("SELECT COUNT(*) FROM alerts LEFT JOIN agents ON agents.id=alerts.agent_id "+where, args...).Scan(&total)

	dataArgs := append(args, perPage, (page-1)*perPage)
	rows, err := database.DB.Query(fmt.Sprintf(`
		SELECT alerts.id, alerts.agent_id, COALESCE(agents.hostname,'')::text,
		       alerts.severity, alerts.rule_name, alerts.fingerprint,
		       alerts.mitre_tactic, alerts.mitre_technique, alerts.mitre_name,
		       alerts.log_message, alerts.created_at,
		       COALESCE(alerts.status,'open'),
		       COALESCE(alerts.acknowledged_by,''),
		       COALESCE(alerts.note,'')
		FROM alerts
		LEFT JOIN agents ON agents.id = alerts.agent_id
		%s
		ORDER BY alerts.created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, idx, idx+1), dataArgs...)

	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type AlertRow struct {
		ID             int    `json:"id"`
		AgentID        int    `json:"agent_id"`
		Hostname       string `json:"hostname"`
		Severity       string `json:"severity"`
		RuleName       string `json:"rule_name"`
		Fingerprint    string `json:"fingerprint"`
		MitreTactic    string `json:"mitre_tactic"`
		MitreTechnique string `json:"mitre_technique"`
		MitreName      string `json:"mitre_name"`
		LogMessage     string `json:"log_message"`
		CreatedAt      string `json:"created_at"`
		Status         string `json:"status"`
		AcknowledgedBy string `json:"acknowledged_by"`
		Note           string `json:"note"`
	}

	var alerts []AlertRow
	for rows.Next() {
		var a AlertRow
		if err := rows.Scan(
			&a.ID, &a.AgentID, &a.Hostname, &a.Severity, &a.RuleName, &a.Fingerprint,
			&a.MitreTactic, &a.MitreTechnique, &a.MitreName,
			&a.LogMessage, &a.CreatedAt,
			&a.Status, &a.AcknowledgedBy, &a.Note,
		); err == nil {
			alerts = append(alerts, a)
		}
	}
	if alerts == nil { alerts = []AlertRow{} }

	pages := total / perPage
	if total%perPage != 0 { pages++ }

	c.JSON(200, gin.H{
		"alerts":   alerts,
		"total":    total,
		"page":     page,
		"per_page": perPage,
		"pages":    pages,
	})
}
