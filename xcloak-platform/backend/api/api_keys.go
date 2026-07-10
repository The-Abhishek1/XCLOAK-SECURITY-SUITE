package api

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// CreateAPIKeyHandler — POST /api/api-keys (admin only)
// Body: { "label": "...", "role": "admin"|"analyst"|"viewer", "expires_in_days": 90 }
// expires_in_days is optional — omit/0 for a key that never expires.
func CreateAPIKeyHandler(c *gin.Context) {

	var body struct {
		Label         string `json:"label"`
		Role          string `json:"role"`
		ExpiresInDays int    `json:"expires_in_days"`
	}

	if err := c.ShouldBindJSON(&body); err != nil || body.Label == "" || body.Role == "" {
		c.JSON(400, gin.H{"error": "label and role are required"})
		return
	}

	var expiresAt *time.Time
	if body.ExpiresInDays > 0 {
		t := time.Now().AddDate(0, 0, body.ExpiresInDays)
		expiresAt = &t
	}

	username, _ := c.Get("username")
	fullKey, key, err := services.CreateAPIKey(tenantIDFromContext(c), username.(string), body.Label, body.Role, expiresAt)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"key":     fullKey, // shown exactly once — never retrievable again
		"api_key": key,
	})
}

// GetAPIKeysHandler — GET /api/api-keys (admin only)
func GetAPIKeysHandler(c *gin.Context) {

	keys, err := services.GetAPIKeys(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if keys == nil {
		keys = []models.APIKey{}
	}

	c.JSON(200, keys)
}

// RevokeAPIKeyHandler — DELETE /api/api-keys/:id (admin only)
func RevokeAPIKeyHandler(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid key id"})
		return
	}

	username, _ := c.Get("username")
	if err := services.RevokeAPIKey(id, tenantIDFromContext(c), username.(string)); err != nil {
		if err == repositories.ErrAPIKeyNotFound {
			c.JSON(404, gin.H{"error": "api key not found"})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "api key revoked"})
}
