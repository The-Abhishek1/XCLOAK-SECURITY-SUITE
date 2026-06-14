package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func GetRiskScore(c *gin.Context) {

	agentID := c.Param("id")

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
