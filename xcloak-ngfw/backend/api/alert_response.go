package api

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

type ResponseAction struct {
	ActionType string         `json:"action_type"`
	Payload    map[string]any `json:"payload"`
}

// DispatchAlertResponse — POST /api/alerts/:id/respond
// Body: { "action_type": "kill_process", "payload": { "pid": 1234 } }
// Dispatches a task to the alert's agent and logs the action.
func DispatchAlertResponse(c *gin.Context) {
	alertID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid alert id"})
		return
	}

	var body ResponseAction
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Allowed action types for manual response
	allowed := map[string]bool{
		"kill_process":          true,
		"kill_process_tree":     true,
		"isolate_host":          true,
		"quarantine_file":       true,
		"delete_dropped_file":   true,
		"delete_registry_key":   true,
		"delete_scheduled_task": true,
		"collect_processes":     true,
		"collect_connections":   true,
		"collect_file_hashes":   true,
		"process_snapshot":      true,
		"memory_dump":           true,
		"fim_scan":              true,
		"vulnerability_scan":    true,
	}
	if !allowed[body.ActionType] {
		c.JSON(400, gin.H{"error": "action_type not permitted: " + body.ActionType})
		return
	}

	// Look up the alert to get agent_id — tenant-scoped, otherwise any
	// authenticated user could dispatch a destructive action (kill_process,
	// isolate_host, quarantine_file) against another tenant's agent just by
	// guessing/incrementing the alert id.
	var agentID int
	var ruleName, severity string
	err = database.DB.QueryRow(
		`SELECT agent_id, rule_name, severity FROM alerts WHERE id=$1 AND tenant_id=$2`, alertID, tenantIDFromContext(c),
	).Scan(&agentID, &ruleName, &severity)
	if err != nil {
		c.JSON(404, gin.H{"error": "alert not found"})
		return
	}

	// Build task payload merging alert context + user payload
	taskPayload := map[string]any{
		"alert_id":  alertID,
		"rule_name": ruleName,
		"severity":  severity,
	}
	for k, v := range body.Payload {
		taskPayload[k] = v
	}
	payloadJSON, _ := json.Marshal(taskPayload)

	task := models.AgentTask{
		AgentID:  agentID,
		TaskType: body.ActionType,
		Payload:  payloadJSON,
	}

	// Destructive actions go through the same pending_approval gate as
	// playbook-dispatched ones — a compromised/malicious session hitting
	// this endpoint directly is no less dangerous than a bad playbook.
	username, _ := c.Get("username")
	user := fmt.Sprintf("%v", username)
	requiresApproval := services.IsDestructiveTask(body.ActionType)
	if requiresApproval {
		err = repositories.CreateTaskPendingApproval(task)
	} else {
		err = repositories.CreateTask(task)
	}
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to dispatch task: " + err.Error()})
		return
	}

	if requiresApproval {
		services.LogEvent(
			"MANUAL_RESPONSE_PENDING_APPROVAL",
			fmt.Sprintf("Alert #%d → %s on agent #%d requested by %s, awaiting approval", alertID, body.ActionType, agentID, user),
			user,
		)
		c.JSON(200, gin.H{
			"message":  "task pending approval",
			"action":   body.ActionType,
			"agent_id": agentID,
			"alert_id": alertID,
		})
		return
	}

	services.LogEvent(
		"MANUAL_RESPONSE",
		fmt.Sprintf("Alert #%d → %s on agent #%d by %s", alertID, body.ActionType, agentID, user),
		user,
	)

	c.JSON(200, gin.H{
		"message":  "task dispatched",
		"action":   body.ActionType,
		"agent_id": agentID,
		"alert_id": alertID,
	})
}

// GetAlertWithTriage — GET /api/alerts/:id
// Returns the alert plus any AI triage data.
func GetAlertWithTriage(c *gin.Context) {
	id := c.Param("id")

	var alert models.Alert
	var aiSummary, aiAction string
	err := database.DB.QueryRow(`
		SELECT id, agent_id, severity, rule_name, fingerprint,
		       mitre_tactic, mitre_technique, mitre_name,
		       log_message, created_at,
		       COALESCE(ai_summary,''), COALESCE(ai_action,'')
		FROM alerts WHERE id=$1 AND tenant_id=$2
	`, id, tenantIDFromContext(c)).Scan(
		&alert.ID, &alert.AgentID, &alert.Severity, &alert.RuleName,
		&alert.Fingerprint, &alert.MitreTactic, &alert.MitreTechnique,
		&alert.MitreName, &alert.LogMessage, &alert.CreatedAt,
		&aiSummary, &aiAction,
	)
	if err != nil {
		c.JSON(404, gin.H{"error": "alert not found"})
		return
	}

	c.JSON(200, gin.H{
		"alert":      alert,
		"ai_summary": aiSummary,
		"ai_action":  aiAction,
	})
}
