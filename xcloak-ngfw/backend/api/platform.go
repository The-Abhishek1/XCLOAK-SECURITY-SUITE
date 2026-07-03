package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

// GetPlatformSummary returns agent + asset counts grouped by platform_category.
// GET /api/assets/platform-summary
func GetPlatformSummary(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	summary, err := services.GetPlatformSummary(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"platform_summary": summary})
}

// GetAgentsByPlatform returns agents filtered by ?platform= query param.
// GET /api/agents?platform=linux
// (platform param handled here; no param falls through to existing GetAgents)
func GetAgentsByPlatform(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	platform := c.Query("platform")

	var agents interface{}
	var err error

	if platform != "" {
		agents, err = repositories.GetAgentsByPlatform(tenantID, platform)
	} else {
		agents, err = repositories.GetAgents(tenantID)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusOK, agents)
}
