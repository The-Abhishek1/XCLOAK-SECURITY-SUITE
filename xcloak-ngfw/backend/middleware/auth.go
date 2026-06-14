package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"xcloak-ngfw/auth"
)

func RequireAuth() gin.HandlerFunc {

	return func(c *gin.Context) {

		// Primary: Authorization header (all normal API calls).
		tokenString := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")

		// Fallback: ?token= query param for SSE/EventSource connections,
		// since browsers cannot set custom headers on EventSource.
		if tokenString == "" {
			tokenString = c.Query("token")
		}

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
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

		c.Set("user_id",  claims["user_id"])
		c.Set("username", claims["username"])
		c.Set("role",     claims["role"])

		c.Next()
	}
}
