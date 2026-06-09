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
