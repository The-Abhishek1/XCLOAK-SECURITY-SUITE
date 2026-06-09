package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/services"
)

func GetAgentSummary(c *gin.Context) {

	agentID := c.Param("id")

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
