package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"xcloak-ngfw/auth"
)

// isDemoRequest checks the request for a demo JWT without depending on
// RequireAuth having run first. It checks (in order):
//  1. The "is_demo" context key set by RequireAuth (if it ran before us)
//  2. The httpOnly "token" cookie, parsed directly
//  3. The Authorization: Bearer header
func isDemoRequest(c *gin.Context) bool {
	// Fast path — RequireAuth already parsed and set this
	if v, exists := c.Get("is_demo"); exists {
		d, _ := v.(bool)
		return d
	}

	var tokenString string
	if cookie, err := c.Request.Cookie("token"); err == nil {
		tokenString = cookie.Value
	}
	if tokenString == "" {
		tokenString = strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	}
	if tokenString == "" {
		return false
	}

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		return auth.JwtSecret(), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !token.Valid {
		return false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}
	demo, _ := claims["demo"].(bool)
	return demo
}

// DemoReadOnly blocks all state-mutating HTTP methods for demo sessions.
// Works at any position in the middleware chain — does not require RequireAuth
// to have run first.
func DemoReadOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isDemoRequest(c) {
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
