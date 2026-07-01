package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/database"
)

// DBCircuit returns a Gin middleware that rejects requests with 503 Service
// Unavailable when the primary database circuit is open (DB unreachable).
// The Retry-After header tells clients and load-balancer health checks how
// long to wait before retrying. Pass-through paths (health, metrics) are
// excluded so the LB can still detect recovery.
func DBCircuit() gin.HandlerFunc {
	// retryAfter matches CIRCUIT_PROBE_INTERVAL — no point retrying faster.
	const retryAfterSeconds = 15

	return func(c *gin.Context) {
		path := c.Request.URL.Path
		// Always allow health and metrics endpoints through — they explicitly
		// report the DB state rather than depending on it.
		if path == "/api/health" || path == "/metrics" || path == "/api/health/deep" {
			c.Next()
			return
		}

		if database.IsPrimaryDown() {
			c.Header("Retry-After", strconv.Itoa(retryAfterSeconds))
			c.Header("X-Circuit-State", "open")
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error":       "database temporarily unavailable",
				"retry_after": retryAfterSeconds,
				"timestamp":   time.Now().UTC(),
			})
			return
		}
		c.Next()
	}
}
