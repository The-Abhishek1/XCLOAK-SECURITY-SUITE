package api

import (
	"net"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/services"
)

// GetNetworkMap — GET /api/network-map?since_minutes=60&limit=500
func GetNetworkMap(c *gin.Context) {

	sinceMinutes := 60
	if v := c.Query("since_minutes"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			sinceMinutes = parsed
		}
	}

	limit := 5000
	if v := c.Query("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	since := time.Now().Add(-time.Duration(sinceMinutes) * time.Minute)

	graph, err := services.BuildNetworkMap(tenantIDFromContext(c), since, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, graph)
}

// GetIPInfo — GET /api/network-map/ip-info?ip=1.2.3.4
// Returns threat intelligence enrichment for an external IP. Results are
// cached in memory for 2 hours to avoid hammering external APIs.
func GetIPInfo(c *gin.Context) {
	ip := c.Query("ip")
	if net.ParseIP(ip) == nil {
		c.JSON(400, gin.H{"error": "invalid IP address"})
		return
	}
	result, err := services.EnrichIP(ip, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

// GetPortInfo — GET /api/network-map/port-info?port=3389
func GetPortInfoHandler(c *gin.Context) {
	port := c.Query("port")
	info := services.GetPortInfo(port)
	if info == nil {
		c.JSON(200, gin.H{"port": port, "service": "", "sensitivity": "neutral", "note": ""})
		return
	}
	c.JSON(200, gin.H{"port": port, "service": info.Service, "sensitivity": info.Sensitivity, "note": info.Note})
}
