package middleware

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// RequireMetricsAuth gates /metrics with a static bearer token from the
// METRICS_TOKEN env var. A user JWT (8h expiry) isn't usable here since
// Prometheus's static scrape config needs one long-lived credential rather
// than a token that needs refreshing every few hours.
func RequireMetricsAuth() gin.HandlerFunc {

	return func(c *gin.Context) {

		expected := os.Getenv("METRICS_TOKEN")
		if expected == "" {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "METRICS_TOKEN not configured"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")

		if tokenString == "" || subtle.ConstantTimeCompare([]byte(tokenString), []byte(expected)) != 1 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid metrics token"})
			c.Abort()
			return
		}

		c.Next()
	}
}
