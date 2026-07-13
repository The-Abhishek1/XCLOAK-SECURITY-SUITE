package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/services"
)

func ReceiveProcesses(c *gin.Context) {

	var processes []models.Process

	if err := c.ShouldBindJSON(&processes); err != nil {

		c.JSON(400, gin.H{
			"error": err.Error(),
		})

		return
	}

	authAgentID := agentIDFromContext(c)
	for i := range processes {
		processes[i].AgentID = authAgentID
	}

	err := services.SaveProcesses(
		processes,
	)

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, gin.H{
		"message": "Processes Received",
	})
}
