package api

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// GetPlatformCapabilities — GET /api/platform/capabilities
// Tells the frontend what this deployment can do, so the UI hides irrelevant
// admin tabs on self-hosted customer instances.
//
// is_authority = true  → this IS the license server (has LICENSE_SIGNING_KEY or
//                        AGENT_RELEASE_SIGNING_KEY set). Shows Deployment Mode
//                        + SaaS & Billing tabs in the Platform page.
// is_authority = false → customer self-hosted copy. Platform page shows
//                        only the Tenants tab. Billing lives in Settings.
func GetPlatformCapabilities(c *gin.Context) {
	hasSigningKey := os.Getenv("LICENSE_SIGNING_KEY") != "" ||
		os.Getenv("AGENT_RELEASE_SIGNING_KEY") != ""

	c.JSON(http.StatusOK, gin.H{
		"is_authority": hasSigningKey,
		"license_mode": services.LicenseModeEnabled(),
		"saas_mode":    services.SaasModeEnabled(),
	})
}

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
