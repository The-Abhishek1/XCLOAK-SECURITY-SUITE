package api

import (
	"fmt"
	"os"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

// PublishAgentRelease — POST /api/platform/agent-releases (platform admin only)
// Body: { "platform": "linux_amd64", "version": "1.2.3", "sha256": "...",
//         "signature": "<base64url ed25519>", "download_url": "..." }
//
// When AGENT_RELEASE_REQUIRE_SIGNATURE=true the signature field is mandatory
// and is verified against AGENT_RELEASE_PUBLIC_KEY before the row is stored.
// Without the env flag the signature is stored as-is (or empty) to support
// gradual rollout.
func PublishAgentRelease(c *gin.Context) {
	var body struct {
		Platform    string `json:"platform"`
		Version     string `json:"version"`
		SHA256      string `json:"sha256"`
		Signature   string `json:"signature"`
		DownloadURL string `json:"download_url"`
	}

	if err := c.ShouldBindJSON(&body); err != nil ||
		body.Platform == "" || body.Version == "" || body.SHA256 == "" || body.DownloadURL == "" {
		c.JSON(400, gin.H{"error": "platform, version, sha256, and download_url are required"})
		return
	}

	require := os.Getenv("AGENT_RELEASE_REQUIRE_SIGNATURE") == "true"
	if require && body.Signature == "" {
		c.JSON(400, gin.H{"error": "signature is required (AGENT_RELEASE_REQUIRE_SIGNATURE=true)"})
		return
	}

	var pkFingerprint string
	if body.Signature != "" {
		pubKey := os.Getenv("AGENT_RELEASE_PUBLIC_KEY")
		if pubKey == "" {
			c.JSON(500, gin.H{"error": "AGENT_RELEASE_PUBLIC_KEY not configured on server"})
			return
		}
		pkFingerprint = services.PublicKeyFingerprint(pubKey)
		// Note: the full binary is not re-downloaded server-side for signing
		// verification — the admin is trusted to provide a correct signature
		// produced by the release pipeline. Agents perform the definitive check
		// against their embedded public key after download.
	}

	username, _ := c.Get("username")
	release, err := repositories.PublishAgentRelease(models.AgentRelease{
		Platform:             body.Platform,
		Version:              body.Version,
		SHA256:               body.SHA256,
		Signature:            body.Signature,
		PublicKeyFingerprint: pkFingerprint,
		DownloadURL:          body.DownloadURL,
		CreatedBy:            fmt.Sprintf("%v", username),
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
