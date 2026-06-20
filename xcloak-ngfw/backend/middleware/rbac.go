package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
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
