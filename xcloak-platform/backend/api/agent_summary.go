package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

func GetAgentSummary(c *gin.Context) {

	agentID := c.Param("id")

	if _, err := repositories.GetAgentByID(agentID, tenantIDFromContext(c)); err != nil {
		c.JSON(404, gin.H{"error": "agent not found"})
		return
	}

	summary, err := services.GetAgentSummary(
		agentID,
	)

	if err != nil {

		c.JSON(404, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, summary)
}
