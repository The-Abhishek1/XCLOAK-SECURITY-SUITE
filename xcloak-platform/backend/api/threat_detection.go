package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/services"
)

// GetAnomalyScores — GET /api/threat/scores?agent_id=N&hours=24
// Returns behavioral anomaly score time series.
func GetAnomalyScores(c *gin.Context) {
	agentID, _ := strconv.Atoi(c.Query("agent_id"))
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours < 1 || hours > 168 {
		hours = 24
	}

	scores, err := services.GetAnomalyScores(agentID, tenantIDFromContext(c), hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if scores == nil {
		scores = []models.AgentAnomalyScore{}
	}
	c.JSON(http.StatusOK, scores)
}

// GetFleetAnomalySummary — GET /api/threat/fleet
// Returns per-agent peak + average scores over the last 24 hours.
func GetFleetAnomalySummary(c *gin.Context) {
	summary, err := services.GetFleetAnomalySummary(tenantIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if summary == nil {
		summary = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, summary)
}

// GetAgentBaselines — GET /api/threat/baselines?agent_id=N
// Returns the 168-bucket hour-of-week baseline for an agent.
func GetAgentBaselines(c *gin.Context) {
	agentID, err := strconv.Atoi(c.Query("agent_id"))
	if err != nil || agentID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id required"})
		return
	}
	baselines, err := services.GetAgentBaselines(agentID, tenantIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if baselines == nil {
		baselines = []models.AgentBaseline{}
	}
	c.JSON(http.StatusOK, baselines)
}

// ScoreAgentNow — POST /api/threat/score/:agent_id
// Triggers an immediate on-demand scoring run for a single agent.
func ScoreAgentNow(c *gin.Context) {
	agentID, err := strconv.Atoi(c.Param("agent_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
		return
	}
	score, err := services.ScoreAgentNow(agentID, tenantIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"agent_id": agentID, "score": score})
}

// AcknowledgeAnomalyFinding — POST /api/threat/findings/:id/acknowledge
func AcknowledgeAnomalyFinding(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := services.AcknowledgeAnomalyFinding(id, tenantIDFromContext(c)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "acknowledged"})
}
