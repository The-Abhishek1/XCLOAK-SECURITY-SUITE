package middleware

import (
	"github.com/gin-gonic/gin"
	"xcloak-platform/services"
)

// SaasGuard blocks tenants whose subscription is suspended, cancelled, or
// whose trial has expired. When SaaS mode is disabled, this is a no-op.
func SaasGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, ok := c.Get("tenant_id")
		if !ok {
			c.Next()
			return
		}
		tid, ok := tenantID.(int)
		if !ok {
			c.Next()
			return
		}
		if !services.CheckTenantAccess(tid) {
			c.AbortWithStatusJSON(402, gin.H{
				"error": "subscription_required",
				"message": "Your subscription has expired or been suspended. " +
					"Please upgrade your plan to continue using XCloak.",
			})
			return
		}
		c.Next()
	}
}
