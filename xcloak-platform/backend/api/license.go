package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/services"
)

// CheckLicenseHandler — POST /api/license/check   (public, no auth)
// Called by self-hosted instances on startup and every 24 h.
// Body (optional): { "key": "xlk_v1...." }
func CheckLicenseHandler(c *gin.Context) {
	var body struct {
		Key string `json:"key"`
	}
	_ = c.ShouldBindJSON(&body)
	resp := services.CheckLicense(body.Key)
	c.JSON(http.StatusOK, resp)
}

// GetLicenseModeHandler — GET /api/platform/license/mode
func GetLicenseModeHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"license_mode": services.LicenseModeEnabled()})
}

// SetLicenseModeHandler — POST /api/platform/license/mode
// Body: { "enabled": true|false }
func SetLicenseModeHandler(c *gin.Context) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := services.SetLicenseMode(body.Enabled); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	msg := map[bool]string{
		true:  "License enforcement enabled — self-hosted instances now require a valid key",
		false: "License enforcement disabled — full open-source access restored",
	}[body.Enabled]
	c.JSON(http.StatusOK, gin.H{"license_mode": body.Enabled, "message": msg})
}

// GenerateLicenseKeyHandler — POST /api/platform/license/keys
// Body: { "customer_name", "customer_email", "tier", "agent_limit", "user_limit", "expires_at", "notes" }
func GenerateLicenseKeyHandler(c *gin.Context) {
	var body struct {
		CustomerName  string `json:"customer_name"`
		CustomerEmail string `json:"customer_email"`
		Tier          string `json:"tier"`
		AgentLimit    int    `json:"agent_limit"`
		UserLimit     int    `json:"user_limit"`
		ExpiresAt     string `json:"expires_at"`
		Notes         string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.CustomerName == "" || body.CustomerEmail == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "customer_name and customer_email are required"})
		return
	}
	if body.Tier == "" {
		body.Tier = "pro"
	}
	if body.AgentLimit == 0 {
		body.AgentLimit = 25
	}
	if body.UserLimit == 0 {
		body.UserLimit = 10
	}

	var expiresAt time.Time
	var err error
	if body.ExpiresAt != "" {
		expiresAt, err = time.Parse("2006-01-02", body.ExpiresAt)
		if err != nil {
			expiresAt, err = time.Parse(time.RFC3339, body.ExpiresAt)
		}
	}
	if expiresAt.IsZero() || err != nil {
		expiresAt = time.Now().AddDate(1, 0, 0) // default: 1 year
	}

	createdBy, _ := c.Get("username")
	rec, err := services.GenerateLicenseKey(
		body.CustomerName, body.CustomerEmail,
		body.Tier, body.AgentLimit, body.UserLimit,
		expiresAt, body.Notes, fmt.Sprintf("%v", createdBy),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rec)
}

// ListLicenseKeysHandler — GET /api/platform/license/keys
func ListLicenseKeysHandler(c *gin.Context) {
	keys, err := services.ListLicenseKeys()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, keys)
}

// RevokeLicenseKeyHandler — DELETE /api/platform/license/keys/:keyID
// Query param: ?reason=...
func RevokeLicenseKeyHandler(c *gin.Context) {
	keyID := c.Param("keyID")
	reason := c.Query("reason")
	if reason == "" {
		reason = "revoked by platform admin"
	}
	if err := services.RevokeLicenseKey(keyID, reason); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "License key revoked"})
}

// RegenerateLicenseTokenHandler — POST /api/platform/license/keys/:keyID/regenerate
func RegenerateLicenseTokenHandler(c *gin.Context) {
	keyID := c.Param("keyID")
	token, err := services.RegenerateLicenseToken(keyID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token})
}
