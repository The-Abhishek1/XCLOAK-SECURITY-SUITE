package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

// SaveFileHashes receives a batch of file hashes from an agent,
// stores them, and runs IOC matching synchronously.
// Route: POST /api/filehashes  (requires agent auth)
func SaveFileHashes(c *gin.Context) {

	var hashes []models.FileHash

	if err := c.ShouldBindJSON(&hashes); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if len(hashes) == 0 {
		c.JSON(400, gin.H{"error": "empty hash batch"})
		return
	}

	if err := services.SaveFileHashes(hashes); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"message": "Hashes saved",
		"count":   len(hashes),
	})
}

// GetAgentFileHashes returns all stored file hashes for a given agent.
// Route: GET /api/agents/:id/filehashes  (requires auth)
func GetAgentFileHashes(c *gin.Context) {

	agentID := c.Param("id")

	hashes, err := services.GetFileHashesByAgent(agentID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if hashes == nil {
		hashes = []models.FileHash{}
	}

	c.JSON(200, hashes)
}
