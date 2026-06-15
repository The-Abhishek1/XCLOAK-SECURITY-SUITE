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
		"kill_process":        true,
		"isolate_host":        true,
		"quarantine_file":     true,
		"collect_processes":   true,
		"collect_connections": true,
		"collect_file_hashes": true,
		"fim_scan":            true,
		"vulnerability_scan":  true,
	}
	if !allowed[body.ActionType] {
		c.JSON(400, gin.H{"error": "action_type not permitted: " + body.ActionType})
		return
	}

	// Look up the alert to get agent_id
	var agentID int
	var ruleName, severity string
	err = database.DB.QueryRow(
		`SELECT agent_id, rule_name, severity FROM alerts WHERE id=$1`, alertID,
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

	err = repositories.CreateTask(models.AgentTask{
		AgentID:  agentID,
		TaskType: body.ActionType,
		Payload:  payloadJSON,
	})
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to dispatch task: " + err.Error()})
		return
	}

	username, _ := c.Get("username")
	user := fmt.Sprintf("%v", username)
	services.LogEvent(
		"MANUAL_RESPONSE",
		fmt.Sprintf("Alert #%d → %s on agent #%d by %s", alertID, body.ActionType, agentID, user),
		user,
	)

	c.JSON(200, gin.H{
		"message":    "task dispatched",
		"action":     body.ActionType,
		"agent_id":   agentID,
		"alert_id":   alertID,
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
		FROM alerts WHERE id=$1
	`, id).Scan(
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
