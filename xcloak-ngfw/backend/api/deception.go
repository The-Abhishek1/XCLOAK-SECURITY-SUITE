package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

// ── Canary Tokens ──────────────────────────────────────────────────────────

func ListCanaryTokens(c *gin.Context) {
	tokens, err := services.GetCanaryTokens(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if tokens == nil {
		tokens = []models.CanaryToken{}
	}
	c.JSON(http.StatusOK, tokens)
}

func CreateCanaryToken(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	var body struct {
		TokenType   string `json:"token_type"`
		Name        string `json:"name"`
		Description string `json:"description"`
		DeployedTo  string `json:"deployed_to"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if body.TokenType == "" {
		body.TokenType = "file"
	}
	tok, err := services.GenerateCanaryToken(tenantID, body.TokenType, body.Name,
		body.Description, body.DeployedTo, usernameFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, tok)
}

func DeleteCanaryToken(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := services.DeleteCanaryToken(id, tenantIDFromContext(c)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

func ToggleCanaryToken(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		Active bool `json:"is_active"`
	}
	c.ShouldBindJSON(&body)
	if err := services.ToggleCanaryToken(id, tenantIDFromContext(c), body.Active); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "updated"})
}

// TripCanaryToken — GET /api/canary/trip/:value (called by an agent or embedded in a document)
func TripCanaryToken(c *gin.Context) {
	tokenValue := c.Param("value")
	extra := map[string]any{
		"path":        c.Request.URL.Path,
		"query":       c.Request.URL.RawQuery,
		"referer":     c.GetHeader("Referer"),
		"accept_lang": c.GetHeader("Accept-Language"),
	}
	_ = services.TripCanaryToken(tokenValue, c.ClientIP(), c.GetHeader("User-Agent"), c.Request.Method, extra)
	// Return 200 with minimal response to avoid fingerprinting
	c.Data(200, "image/gif", transparentGIF)
}

// 1x1 transparent GIF — canary URL responses look like a tracker pixel
var transparentGIF = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80,
	0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21, 0xf9, 0x04,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
}

func GetCanaryTrips(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	tokenID, _ := strconv.Atoi(c.DefaultQuery("token_id", "0"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	trips, err := services.GetCanaryTrips(tenantID, tokenID, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if trips == nil {
		trips = []models.CanaryTrip{}
	}
	c.JSON(http.StatusOK, trips)
}

// ── Honeyports ─────────────────────────────────────────────────────────────

func ListHoneyports(c *gin.Context) {
	ports, err := services.GetHoneyports(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if ports == nil {
		ports = []models.Honeyport{}
	}
	c.JSON(http.StatusOK, ports)
}

func CreateHoneyport(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	var body struct {
		AgentID     int    `json:"agent_id"`
		Port        int    `json:"port"`
		Protocol    string `json:"protocol"`
		Description string `json:"description"`
		Severity    string `json:"alert_severity"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if body.Protocol == "" {
		body.Protocol = "tcp"
	}
	if body.Severity == "" {
		body.Severity = "high"
	}
	h, err := services.CreateHoneyport(tenantID, body.AgentID, body.Port, body.Protocol, body.Description, body.Severity)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, h)
}

func DeleteHoneyport(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := services.DeleteHoneyport(id, tenantIDFromContext(c)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}
