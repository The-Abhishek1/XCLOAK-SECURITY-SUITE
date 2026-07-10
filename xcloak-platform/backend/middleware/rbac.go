package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"xcloak-platform/services"
)

func RequireRole(
	requiredRole string,
) gin.HandlerFunc {

	return func(c *gin.Context) {

		role, exists := c.Get("role")

		if !exists {

			c.JSON(http.StatusForbidden, gin.H{
				"error": "role missing",
			})

			c.Abort()
			return
		}

		if role != requiredRole {

			c.JSON(http.StatusForbidden, gin.H{
				"error": "access denied",
			})

			c.Abort()
			return
		}

		c.Next()
	}
}

// RequirePermission gates an action by permission rather than by exact role
// match — admin always passes (unchanged superuser behavior); a custom role
// passes only if it was explicitly granted perm. analyst/viewer never match
// a custom role, so they're denied exactly as RequireRole("admin") already
// denied them before this existed — zero behavior change for anyone not on
// a custom role.
func RequirePermission(perm string) gin.HandlerFunc {

	return func(c *gin.Context) {

		role, _ := c.Get("role")
		roleStr, _ := role.(string)

		tenantID := 1
		if v, exists := c.Get("tenant_id"); exists {
			switch t := v.(type) {
			case int:
				tenantID = t
			case float64:
				tenantID = int(t)
			}
		}

		if !services.HasPermission(roleStr, tenantID, perm) {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequirePlatformAdmin gates platform-operator actions (tenant provisioning)
// that are independent of — and a strict superset of — the per-tenant admin
// role. is_platform_admin is never set via any API; it's promoted by direct
// SQL only, so there is no self-escalation path through this middleware.
func RequirePlatformAdmin() gin.HandlerFunc {

	return func(c *gin.Context) {

		isPlatformAdmin, _ := c.Get("is_platform_admin")

		if isPlatformAdmin != true {

			c.JSON(http.StatusForbidden, gin.H{
				"error": "platform admin access required",
			})

			c.Abort()
			return
		}

		c.Next()
	}
}
