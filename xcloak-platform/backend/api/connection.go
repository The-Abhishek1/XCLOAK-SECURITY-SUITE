package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/services"
)

func ReceiveConnections(c *gin.Context) {

	var connections []models.Connection

	if err := c.ShouldBindJSON(&connections); err != nil {

		c.JSON(400, gin.H{
			"error": err.Error(),
		})

		return
	}

	authAgentID := agentIDFromContext(c)
	for i := range connections {
		connections[i].AgentID = authAgentID
	}

	err := services.SaveConnections(
		connections,
	)

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, gin.H{
		"message": "Connections Received",
	})
}
