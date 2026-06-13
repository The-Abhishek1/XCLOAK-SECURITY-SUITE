package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/middleware"
	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

// RegisterAgent upserts the agent by machine_id.
// Returns agent_id + token on first registration.
// Returns the SAME agent_id + token on re-registration (agent restart).
// No auth required — the token is the output of this call.
func RegisterAgent(c *gin.Context) {

	var agent models.Agent

	if err := c.ShouldBindJSON(&agent); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if agent.MachineID == "" {
		c.JSON(400, gin.H{"error": "machine_id is required"})
		return
	}

	agentID, token, err := services.RegisterAgent(agent)

	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"agent_id": agentID,
		"token":    token,
		"message":  "Agent registered",
	})
}

func GetAgents(c *gin.Context) {

	agents, err := services.GetAgents()

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, agents)
}

func GetAgentByID(c *gin.Context) {

	id := c.Param("id")

	agent, err := services.GetAgentByID(id)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
		return
	}

	c.JSON(http.StatusOK, agent)
}

// Heartbeat updates last_seen. Agent ID comes from the validated token context,
// NOT from the request body — so a rogue agent can't update another agent's status.
func Heartbeat(c *gin.Context) {

	agent := middleware.AgentFromContext(c)

	if err := services.Heartbeat(agent.ID); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "Heartbeat received"})
}
