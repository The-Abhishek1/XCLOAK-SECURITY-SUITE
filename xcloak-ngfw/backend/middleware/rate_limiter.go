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
// Default: 120 requests per 60 seconds per IP.
// Auth endpoints get a tighter limit (10 req/min) to slow brute force.

var ctx = context.Background()

// rlScript atomically removes stale entries, checks the window count, and
// adds the new member in a single round-trip. The two-pipeline approach had
// a TOCTOU race: between the cardinality check and the subsequent ZADD,
// concurrent requests could both see count < limit and both proceed,
// effectively allowing 2× the intended limit under burst load. Lua scripts
// run atomically on Redis — no interleaving is possible.
var rlScript = redis.NewScript(`
local key     = KEYS[1]
local cutoff  = ARGV[1]
local limit   = tonumber(ARGV[2])
local score   = ARGV[3]
local member  = ARGV[4]
local ttl_ms  = tonumber(ARGV[5])

redis.call('ZREMRANGEBYSCORE', key, '0', cutoff)
local count = redis.call('ZCARD', key)
if count >= limit then
    return 0
end
redis.call('ZADD', key, score, member)
redis.call('PEXPIRE', key, ttl_ms)
return 1
`)

// isAllowed returns true if the key is within the sliding-window limit.
func isAllowed(key string, limit int, window time.Duration) bool {
	redisKey := "ratelimit:" + key
	now := time.Now()
	nowNS := now.UnixNano()
	cutoff := now.Add(-window).UnixNano()
	member := fmt.Sprintf("%d", nowNS)
	ttlMS := window.Milliseconds()

	result, err := rlScript.Run(ctx, services.RDB,
		[]string{redisKey},
		fmt.Sprintf("%d", cutoff),
		limit,
		fmt.Sprintf("%d", nowNS),
		member,
		ttlMS,
	).Int()
	if err != nil {
		// Redis unavailable — fail open rather than block all traffic.
		return true
	}
	return result == 1
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
