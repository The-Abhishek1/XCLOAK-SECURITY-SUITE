package api

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/services"
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
