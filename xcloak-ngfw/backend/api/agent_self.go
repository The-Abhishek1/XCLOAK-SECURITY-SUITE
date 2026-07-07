package api

// Agent self-access endpoints — authenticated with the agent bearer token
// (RequireAgentAuth), not a user JWT. These return data scoped to the
// calling agent only, so the mobile agent shell can display its own
// monitoring data without needing user credentials.

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/middleware"
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

func selfAgent(c *gin.Context) (*models.Agent, bool) {
	v, exists := c.Get(middleware.AgentKey)
	if !exists {
		c.JSON(401, gin.H{"error": "agent not authenticated"})
		return nil, false
	}
	agent, ok := v.(*models.Agent)
	if !ok || agent == nil {
		c.JSON(401, gin.H{"error": "agent not authenticated"})
		return nil, false
	}
	return agent, true
}

// GetSelfSummary — GET /api/agents/self/summary
// Returns the summary for the calling agent.
func GetSelfSummary(c *gin.Context) {
	agent, ok := selfAgent(c)
	if !ok {
		return
	}
	summary, err := services.GetAgentSummary(fmt.Sprintf("%d", agent.ID))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, summary)
}

// GetSelfAlerts — GET /api/agents/self/alerts
// Returns alerts scoped to the calling agent.
func GetSelfAlerts(c *gin.Context) {
	agent, ok := selfAgent(c)
	if !ok {
		return
	}
	alerts, err := repositories.GetAlertsByAgentID(agent.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if alerts == nil {
		alerts = []models.Alert{}
	}
	c.JSON(200, gin.H{"alerts": alerts, "total": len(alerts)})
}

// GetSelfTimeline — GET /api/agents/self/timeline
// Returns the event timeline for the calling agent.
func GetSelfTimeline(c *gin.Context) {
	agent, ok := selfAgent(c)
	if !ok {
		return
	}
	timeline, err := services.GetAgentTimeline(agent.ID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, timeline)
}
