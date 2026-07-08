package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// DemoReadOnly blocks all state-mutating HTTP methods for demo sessions.
// Must be applied after RequireAuth() so the "is_demo" context key is set.
func DemoReadOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		isDemo, _ := c.Get("is_demo")
		if isDemo != true {
			c.Next()
			return
		}
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
		default:
			c.JSON(http.StatusForbidden, gin.H{
				"error": "demo mode — this action is disabled in the live demo",
			})
			c.Abort()
		}
	}
}
