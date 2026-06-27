package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// PublishAgentRelease — POST /api/platform/agent-releases (platform admin only)
// Body: { "platform": "linux_amd64", "version": "1.2.3", "sha256": "...", "download_url": "..." }
func PublishAgentRelease(c *gin.Context) {
	var body struct {
		Platform    string `json:"platform"`
		Version     string `json:"version"`
		SHA256      string `json:"sha256"`
		DownloadURL string `json:"download_url"`
	}

	if err := c.ShouldBindJSON(&body); err != nil ||
		body.Platform == "" || body.Version == "" || body.SHA256 == "" || body.DownloadURL == "" {
		c.JSON(400, gin.H{"error": "platform, version, sha256, and download_url are required"})
		return
	}

	username, _ := c.Get("username")
	release, err := repositories.PublishAgentRelease(models.AgentRelease{
		Platform:    body.Platform,
		Version:     body.Version,
		SHA256:      body.SHA256,
		DownloadURL: body.DownloadURL,
		CreatedBy:   fmt.Sprintf("%v", username),
	})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, release)
}

// GetAgentReleases — GET /api/platform/agent-releases (platform admin only)
func GetAgentReleases(c *gin.Context) {
	releases, err := repositories.GetAgentReleases()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if releases == nil {
		releases = []models.AgentRelease{}
	}
	c.JSON(200, releases)
}

// GetLatestAgentRelease — GET /api/agent-releases/:platform (agent auth)
// What the agent's self-update checker actually calls.
func GetLatestAgentRelease(c *gin.Context) {
	release, err := repositories.GetAgentReleaseByPlatform(c.Param("platform"))
	if err != nil {
		c.JSON(404, gin.H{"error": "no release published for this platform"})
		return
	}
	c.JSON(200, release)
}
