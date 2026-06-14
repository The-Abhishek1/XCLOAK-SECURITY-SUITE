package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter implements a per-IP sliding-window rate limiter backed by an
// in-process map. No external dependency required (Redis can replace this
// in Phase 5 for multi-instance deployments).
//
// Default: 100 requests per 60 seconds per IP.
// Auth endpoints get a tighter limit (10 req/min) to slow brute force.

type windowEntry struct {
	timestamps []time.Time
	mu         sync.Mutex
}

type rateLimiterStore struct {
	mu      sync.RWMutex
	entries map[string]*windowEntry
}

var globalStore = &rateLimiterStore{
	entries: make(map[string]*windowEntry),
}

func (s *rateLimiterStore) get(key string) *windowEntry {
	s.mu.RLock()
	e, ok := s.entries[key]
	s.mu.RUnlock()
	if ok {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e = &windowEntry{}
	s.entries[key] = e
	return e
}

// isAllowed returns true if the key has fewer than limit requests in the
// last window duration.
func isAllowed(key string, limit int, window time.Duration) bool {

	e := globalStore.get(key)
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)

	// Drop timestamps outside the window.
	valid := e.timestamps[:0]
	for _, t := range e.timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	e.timestamps = valid

	if len(e.timestamps) >= limit {
		return false
	}

	e.timestamps = append(e.timestamps, now)
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
