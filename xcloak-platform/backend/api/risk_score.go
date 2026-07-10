package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

func GetRiskScore(c *gin.Context) {

	agentID := c.Param("id")

	if _, err := repositories.GetAgentByID(agentID, tenantIDFromContext(c)); err != nil {
		c.JSON(404, gin.H{"error": "agent not found"})
		return
	}

	score, err := repositories.GetRiskScore(agentID)
	if err != nil {
		// No risk score yet (agent just registered, no alerts/vulns).
		// Return a zero score so the frontend can display 0 rather than erroring.
		c.JSON(200, models.AssetRiskScore{
			RiskScore: 0,
			RiskLevel: "low",
		})
		return
	}

	c.JSON(200, score)
}
