package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
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

	feedIDInt := 0
	fmt.Sscanf(id, "%d", &feedIDInt)
	tenantID := tenantIDFromContext(c)

	count, err := services.SyncThreatFeed(*feed)

	syncStatus := "success"
	errMsg := ""
	if err != nil {
		syncStatus = "error"
		errMsg = fmt.Sprintf("%s: %d imported before error: %v", feed.Name, count, err)
	}
	repositories.CreateFeedSyncLog(models.FeedSyncLog{
		FeedID: feedIDInt, TenantID: tenantID, Status: syncStatus, IOCsAdded: count, ErrorMessage: errMsg,
	})

	if err != nil {
		services.LogEvent("SYNC_THREAT_FEED_PARTIAL", errMsg, user)
		c.JSON(502, gin.H{"error": err.Error(), "count": count})
		return
	}

	services.LogEvent("SYNC_THREAT_FEED", feed.Name, user)

	c.JSON(200, gin.H{
		"message": "Feed Synced",
		"count":   count,
	})
}
