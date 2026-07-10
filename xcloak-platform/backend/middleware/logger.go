package middleware

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
)

// RequestLogger logs each request as a structured slog record after the
// response is written. Fields match what most SIEM/log-aggregation stacks
// expect: method, path, status, latency, client_ip, request_id.
//
// request_id is populated by RequireID() which runs after this middleware
// in the chain — by the time c.Next() returns here, RequestID() has already
// stored the UUID in the context and set the X-Request-ID response header.
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()

		reqID, _ := c.Get("request_id")
		reqIDStr, _ := reqID.(string)

		level := slog.LevelInfo
		if status >= 500 {
			level = slog.LevelError
		} else if status >= 400 {
			level = slog.LevelWarn
		}

		slog.Log(c.Request.Context(), level, "http",
			"method",     c.Request.Method,
			"path",       c.Request.URL.Path,
			"status",     status,
			"latency_ms", latency.Milliseconds(),
			"client_ip",  c.ClientIP(),
			"request_id", reqIDStr,
		)
	}
}
