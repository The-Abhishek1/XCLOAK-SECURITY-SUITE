package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

// SyncThreatFeed — POST /api/threat-feeds/:id/sync
// Fetches the feed's source URL, imports indicators as IOCs, and updates
// last_sync. Returns the count of indicators processed.
func SyncThreatFeed(c *gin.Context) {

	id := c.Param("id")

	feed, err := repositories.GetThreatFeedByID(id)
	if err != nil {
		c.JSON(404, gin.H{"error": "feed not found"})
		return
	}

	count, err := services.SyncThreatFeed(*feed)
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}

	services.LogEvent("SYNC_THREAT_FEED", feed.Name, "admin")

	c.JSON(200, gin.H{
		"message": "Feed Synced",
		"count":   count,
	})
}
