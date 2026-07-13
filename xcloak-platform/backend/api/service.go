package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/services"
)

func ReceiveServices(c *gin.Context) {

	var servicesData []models.Service

	if err := c.ShouldBindJSON(&servicesData); err != nil {

		c.JSON(400, gin.H{
			"error": err.Error(),
		})

		return
	}

	authAgentID := agentIDFromContext(c)
	for i := range servicesData {
		servicesData[i].AgentID = authAgentID
	}

	err := services.SaveServices(
		servicesData,
	)

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, gin.H{
		"message": "Services Received",
	})
}
