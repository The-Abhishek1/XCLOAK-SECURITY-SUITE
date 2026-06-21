package api

import (
	"encoding/json"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

// TriageAlert — POST /api/ai/triage/:alert_id
// Triggers AI triage for a specific alert and returns the result.
func TriageAlertHandler(c *gin.Context) {

	alertID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid alert id"})
		return
	}

	// Fetch the alert.
	alerts, err := services.GetAlerts(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	var target *models.Alert
	for _, a := range alerts {
		if a.ID == alertID {
			alert := a
			target = &alert
			break
		}
	}

	if target == nil {
		c.JSON(404, gin.H{"error": "alert not found"})
		return
	}

	// Run triage synchronously for on-demand requests (async for auto-triage).
	services.TriageAlert(*target)

	c.JSON(200, gin.H{"message": "Triage complete"})
}

// SummarizeIncident — POST /api/ai/incidents/:id/summarize
// Returns an AI-generated incident narrative.
func SummarizeIncidentHandler(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid incident id"})
		return
	}

	summary, err := services.SummarizeIncident(id, tenantIDFromContext(c))
	if err != nil {
		c.JSON(502, gin.H{"error": "AI unavailable: " + err.Error()})
		return
	}

	c.JSON(200, summary)
}

// RunAnomalyDetection — POST /api/ai/anomaly/:agent_id
// Triggers AI anomaly detection for an agent.
func RunAnomalyDetectionHandler(c *gin.Context) {

	agentID, err := strconv.Atoi(c.Param("agent_id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid agent id"})
		return
	}
	if !agentOwnedBy404(c, c.Param("agent_id")) {
		return
	}

	findings, err := services.RunAnomalyDetection(agentID)
	if err != nil {
		c.JSON(502, gin.H{"error": "AI unavailable: " + err.Error()})
		return
	}

	if findings == nil {
		findings = []models.AnomalyFinding{}
	}

	c.JSON(200, gin.H{
		"agent_id": agentID,
		"findings": findings,
		"count":    len(findings),
	})
}

// GetAnomalies — GET /api/ai/anomalies?agent_id=N
func GetAnomaliesHandler(c *gin.Context) {

	agentID := c.Query("agent_id")

	findings, err := services.GetAnomalies(agentID, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if findings == nil {
		findings = []models.AnomalyFinding{}
	}

	c.JSON(200, findings)
}

// AIChat — POST /api/ai/chat
// Body: { "message": "...", "history": [...] }
func AIChatHandler(c *gin.Context) {

	username, _ := c.Get("username")
	user := "admin"
	if username != nil {
		user = username.(string)
	}

	var body struct {
		Message string               `json:"message"`
		History []models.ChatMessage `json:"history"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if body.Message == "" {
		c.JSON(400, gin.H{"error": "message is required"})
		return
	}

	response, updatedHistory, err := services.ChatWithAssistant(user, body.Message, body.History, tenantIDFromContext(c))
	if err != nil {
		c.JSON(502, gin.H{"error": "AI unavailable: " + err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"response": response,
		"history":  updatedHistory,
	})
}

// GetChatHistory — GET /api/ai/chat/history
func GetChatHistoryHandler(c *gin.Context) {

	username, _ := c.Get("username")
	user := "admin"
	if username != nil {
		user = username.(string)
	}

	history, err := services.GetChatHistory(user, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"history": history})
}

// ClearChatHistory — DELETE /api/ai/chat/history
func ClearChatHistoryHandler(c *gin.Context) {

	username, _ := c.Get("username")
	user := "admin"
	if username != nil {
		user = username.(string)
	}

	services.ClearChatHistory(user, tenantIDFromContext(c))
	c.JSON(200, gin.H{"message": "Chat history cleared"})
}

// suppress unused import
var _ = json.Marshal
