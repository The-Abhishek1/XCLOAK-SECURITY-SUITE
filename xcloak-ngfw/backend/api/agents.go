package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

func RegisterAgent(c *gin.Context) {

	var agent models.Agent

	if err := c.ShouldBindJSON(&agent); err != nil {

		c.JSON(400, gin.H{
			"error": err.Error(),
		})

		return
	}

	agentID, err := services.RegisterAgent(agent)

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, gin.H{
		"agent_id": agentID,
		"message":  "Agent Registered",
	})
}

func GetAgents(c *gin.Context) {

	agents, err := services.GetAgents()

	if err != nil {

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(http.StatusOK, agents)
}

func GetAgentByID(c *gin.Context) {

	id := c.Param("id")

	agent, err := services.GetAgentByID(id)

	if err != nil {

		c.JSON(http.StatusNotFound, gin.H{
			"error": "Agent not found",
		})

		return
	}

	c.JSON(http.StatusOK, agent)
}

func Heartbeat(c *gin.Context) {

	var req models.HeartbeatRequest

	if err := c.ShouldBindJSON(&req); err != nil {

		c.JSON(400, gin.H{
			"error": err.Error(),
		})

		return
	}

	err := services.Heartbeat(
		req.AgentID,
	)

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, gin.H{
		"message": "Heartbeat Received",
	})
}
