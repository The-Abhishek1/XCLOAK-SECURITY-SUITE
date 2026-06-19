package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"xcloak-ngfw/services"
)

// Sliding-window rate limiter backed by Redis (sorted set per key), so
// limits survive a backend restart and stay consistent across replicas.
//
// Default: 100 requests per 60 seconds per IP.
// Auth endpoints get a tighter limit (10 req/min) to slow brute force.

var ctx = context.Background()

// isAllowed returns true if the key has fewer than limit requests in the
// last window duration. Uses a Redis sorted set: each request is scored by
// its timestamp, old entries are trimmed, then the set size is checked —
// all within one pipeline so concurrent requests don't race past the limit.
func isAllowed(key string, limit int, window time.Duration) bool {

	redisKey := "ratelimit:" + key
	now := time.Now()
	cutoff := now.Add(-window).UnixNano()
	member := fmt.Sprintf("%d", now.UnixNano())

	pipe := services.RDB.Pipeline()
	pipe.ZRemRangeByScore(ctx, redisKey, "0", fmt.Sprintf("%d", cutoff))
	card := pipe.ZCard(ctx, redisKey)
	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		// Redis unavailable — fail open rather than block all traffic.
		return true
	}

	if card.Val() >= int64(limit) {
		return false
	}

	pipe2 := services.RDB.Pipeline()
	pipe2.ZAdd(ctx, redisKey, redis.Z{Score: float64(now.UnixNano()), Member: member})
	pipe2.Expire(ctx, redisKey, window)
	pipe2.Exec(ctx)

	return true
}

// RateLimit returns a Gin middleware that applies a sliding-window rate limit.
//   - limit: max requests allowed
//   - window: duration of the window (e.g. 60 * time.Second)
func RateLimit(limit int, window time.Duration) gin.HandlerFunc {

	return func(c *gin.Context) {

		ip := c.ClientIP()
		key := ip + ":" + c.FullPath()

		if !isAllowed(key, limit, window) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded — slow down",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Convenience constructors for common limits.

// RateLimitAPI applies a generous limit suitable for normal API usage.
// 120 requests per minute per IP.
func RateLimitAPI() gin.HandlerFunc {
	return RateLimit(120, time.Minute)
}

// RateLimitAuth applies a tight limit to login/register to slow brute force.
// 10 requests per minute per IP.
func RateLimitAuth() gin.HandlerFunc {
	return RateLimit(10, time.Minute)
}
