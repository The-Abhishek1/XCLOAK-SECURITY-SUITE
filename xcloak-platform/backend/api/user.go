package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/services"
)

func ReceiveUsers(c *gin.Context) {

	users := []models.Users{}

	if err := c.ShouldBindJSON(&users); err != nil {

		c.JSON(400, gin.H{
			"error": err.Error(),
		})

		return
	}

	authAgentID := agentIDFromContext(c)
	for i := range users {
		users[i].AgentID = authAgentID
	}

	err := services.SaveUsers(users)

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, gin.H{
		"message": "Users Received",
	})
}
