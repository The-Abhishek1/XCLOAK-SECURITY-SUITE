package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"xcloak-ngfw/auth"
	"xcloak-ngfw/services"
)

func RequireAuth() gin.HandlerFunc {

	return func(c *gin.Context) {

		// 1. Try Authorization header (all normal API calls).
		tokenString := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")

		// 2. Fall back to ?token= query param for WebSocket / EventSource,
		//    since browsers cannot set custom headers on WS or EventSource.
		if tokenString == "" {
			tokenString = c.Query("token")
		}

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			c.Abort()
			return
		}

		// 3. Check blacklist (revoked on logout).
		if services.IsRevoked(tokenString) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "token has been revoked — please log in again"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return auth.JwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		claims := token.Claims.(jwt.MapClaims)

		// Reject refresh tokens used as access tokens.
		if claims["type"] == "refresh" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh tokens cannot be used for API access"})
			c.Abort()
			return
		}

		c.Set("user_id",      claims["user_id"])
		c.Set("username",     claims["username"])
		c.Set("role",         claims["role"])
		c.Set("token_string", tokenString) // stored for logout

		c.Next()
	}
}
