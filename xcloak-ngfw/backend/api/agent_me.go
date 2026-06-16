package api

import (
	"github.com/gin-gonic/gin"
	"xcloak-ngfw/database"
)

// GetCurrentAgent — GET /api/agents/me
// Called by an already-registered agent on startup to resume its session.
// Uses RequireAgentAuth() — agent bearer token.
func GetCurrentAgent(c *gin.Context) {
	agentID, exists := c.Get("agent_id")
	if !exists {
		c.JSON(401, gin.H{"error": "not authenticated as agent"})
		return
	}

	var hostname, status string
	err := database.DB.QueryRow(
		`SELECT hostname, status FROM agents WHERE id=$1`, agentID,
	).Scan(&hostname, &status)

	if err != nil {
		c.JSON(404, gin.H{"error": "agent not found"})
		return
	}

	c.JSON(200, gin.H{
		"agent_id": agentID,
		"hostname": hostname,
		"status":   status,
	})
}
