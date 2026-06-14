package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

// RegisterAgent — POST /api/agents/register
// Returns agent_id + the hex token stored in the DB (generated once per machine_id).
func RegisterAgent(c *gin.Context) {

	var reg models.AgentRegistration

	if err := c.ShouldBindJSON(&reg); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	agent := models.Agent{
		MachineID: reg.MachineID,
		Hostname:  reg.Hostname,
		OS:        reg.OS,
		IPAddress: reg.IPAddress,
	}

	// services.RegisterAgent returns (agentID int, token string, err error)
	// The token is a random hex string stored in agents.token column.
	agentID, token, err := services.RegisterAgent(agent)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"agent_id": agentID,
		"message":  "Agent Registered",
		"token":    token,
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

func Heartbeat(c *gin.Context) {

	var req models.HeartbeatRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := services.Heartbeat(req.AgentID); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "Heartbeat Received"})
}
