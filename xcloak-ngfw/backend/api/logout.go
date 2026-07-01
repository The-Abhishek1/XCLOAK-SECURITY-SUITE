package api

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"xcloak-ngfw/auth"
	"xcloak-ngfw/services"
)

// Logout — POST /api/auth/logout
// Revokes the current JWT so it can't be reused even within its 8h window.
func Logout(c *gin.Context) {
	tokenString := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	// Also accept the httpOnly session cookie.
	if tokenString == "" {
		if cookie, err := c.Request.Cookie("token"); err == nil {
			tokenString = cookie.Value
		}
	}
	if tokenString == "" {
		clearAuthCookies(c)
		c.JSON(200, gin.H{"message": "logged out"})
		return
	}

	// Parse to get expiry time for blacklist TTL.
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return auth.JwtSecret(), nil
	})

	expiry := time.Now().Add(8 * time.Hour) // fallback
	if err == nil && token.Valid {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if exp, ok := claims["exp"].(float64); ok {
				expiry = time.Unix(int64(exp), 0)
			}
		}
	}

	services.RevokeToken(tokenString, expiry)
	clearAuthCookies(c)

	username, _ := c.Get("username")
	services.LogEvent("LOGOUT", "user logged out", func() string {
		if username != nil {
			return username.(string)
		}
		return "unknown"
	}())

	c.JSON(200, gin.H{"message": "logged out successfully"})
}
