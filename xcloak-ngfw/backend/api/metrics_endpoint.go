package api

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsHandler exposes the Prometheus /metrics endpoint.
// Register with: router.GET("/metrics", api.MetricsHandler)
// No auth — Prometheus scraper doesn't send JWT.
// Restrict via firewall/network: only allow Prometheus server IP.
func MetricsHandler() gin.HandlerFunc {
	h := promhttp.Handler()
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}
