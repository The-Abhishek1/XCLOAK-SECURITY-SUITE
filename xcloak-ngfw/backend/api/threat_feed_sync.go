package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

// SyncThreatFeed — POST /api/threat-feeds/:id/sync
// Fetches the feed's source URL, imports indicators as IOCs, and updates
// last_sync. Returns the count of indicators processed.
func SyncThreatFeed(c *gin.Context) {

	id := c.Param("id")

	feed, err := repositories.GetThreatFeedByID(id, tenantIDFromContext(c))
	if err != nil {
		c.JSON(404, gin.H{"error": "feed not found"})
		return
	}

	username, _ := c.Get("username")
	user := fmt.Sprintf("%v", username)

	count, err := services.SyncThreatFeed(*feed)
	if err != nil {
		// Connector feeds (otx/misp/taxii) paginate and may import a real
		// partial batch before a later page errors — surface that count
		// rather than discarding it, since those indicators are genuinely
		// in the IOC table already.
		services.LogEvent("SYNC_THREAT_FEED_PARTIAL", fmt.Sprintf("%s: %d imported before error: %v", feed.Name, count, err), user)
		c.JSON(502, gin.H{"error": err.Error(), "count": count})
		return
	}

	services.LogEvent("SYNC_THREAT_FEED", feed.Name, user)

	c.JSON(200, gin.H{
		"message": "Feed Synced",
		"count":   count,
	})
}
