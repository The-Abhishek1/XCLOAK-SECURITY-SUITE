package api

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"xcloak-platform/services"
)

// GetMySubscriptionHandler — GET /api/billing/subscription
func GetMySubscriptionHandler(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	sub, err := services.GetSubscription(tenantID)
	if err != nil {
		// No subscription row yet (e.g. demo tenant) — return a synthetic trial.
		usage := services.GetTenantUsage(tenantID)
		c.JSON(200, gin.H{
			"subscription": gin.H{
				"plan_name":         "trial",
				"plan_display_name": "Free Trial",
				"status":            "trial",
				"max_agents":        10,
				"max_users":         3,
				"features":          gin.H{},
			},
			"usage": usage,
		})
		return
	}
	usage := services.GetTenantUsage(tenantID)
	c.JSON(200, gin.H{
		"subscription": sub,
		"usage":        usage,
	})
}

// GetPlansHandler — GET /api/billing/plans
func GetPlansHandler(c *gin.Context) {
	plans, err := services.GetAllPlans()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, plans)
}

// RequestUpgradeHandler — POST /api/billing/request-upgrade
// Records the upgrade intent in the audit log so the platform admin can
// action it manually (Stripe wired in a later phase).
func RequestUpgradeHandler(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	username, _ := c.Get("username")

	var body struct {
		Plan    string `json:"plan"`
		Message string `json:"message"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Plan == "" {
		c.JSON(400, gin.H{"error": "plan is required"})
		return
	}

	u := "unknown"
	if s, ok := username.(string); ok {
		u = s
	}

	services.LogEvent("BILLING_UPGRADE_REQUEST",
		fmt.Sprintf("tenant_id=%d requested_plan=%s msg=%s", tenantID, body.Plan, body.Message),
		u,
	)

	c.JSON(200, gin.H{"message": "Upgrade request received. Our team will contact you within 24 hours."})
}
