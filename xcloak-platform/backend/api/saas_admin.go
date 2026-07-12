package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"xcloak-platform/models"
	"xcloak-platform/services"
)

// GetSaasStatsHandler — GET /api/platform/saas/stats
func GetSaasStatsHandler(c *gin.Context) {
	stats, err := services.GetSaasStats()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, stats)
}

// GetAllSubscriptionsHandler — GET /api/platform/saas/subscriptions
func GetAllSubscriptionsHandler(c *gin.Context) {
	subs, err := services.GetAllSubscriptions()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if subs == nil {
		subs = []models.Subscription{}
	}
	c.JSON(200, subs)
}

// UpdateSubscriptionHandler — PATCH /api/platform/saas/subscriptions/:tenantID
// Body: { "plan": "starter|growth|pro|enterprise", "status": "active|trial|suspended|cancelled", "notes": "..." }
func UpdateSubscriptionHandler(c *gin.Context) {
	tenantID, err := strconv.Atoi(c.Param("tenantID"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid tenant id"})
		return
	}
	var body struct {
		Plan   string  `json:"plan"`
		Status string  `json:"status"`
		Notes  *string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := services.UpdateSubscription(tenantID, body.Plan, body.Status, body.Notes); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "subscription updated"})
}

// GetSaasModeHandler — GET /api/platform/saas/mode
func GetSaasModeHandler(c *gin.Context) {
	c.JSON(200, gin.H{"saas_mode": services.SaasModeEnabled()})
}

// SetSaasModeHandler — POST /api/platform/saas/mode
// Body: { "enabled": true|false }
func SetSaasModeHandler(c *gin.Context) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := services.SetSaasMode(body.Enabled); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"saas_mode": body.Enabled, "message": map[bool]string{true: "SaaS mode enabled", false: "SaaS mode disabled"}[body.Enabled]})
}

// GetAllPlansHandler — GET /api/platform/saas/plans
func GetAllPlansHandler(c *gin.Context) {
	plans, err := services.GetAllPlans()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, plans)
}
