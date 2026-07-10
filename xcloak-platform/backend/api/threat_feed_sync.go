package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// UpdateThreatFeed — PUT /api/threat-feeds/:id
func UpdateThreatFeed(c *gin.Context) {
	id := c.Param("id")
	var feed models.ThreatFeed
	if err := c.ShouldBindJSON(&feed); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := repositories.UpdateThreatFeed(id, feed, tenantIDFromContext(c)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "updated"})
}

// DeleteThreatFeed — DELETE /api/threat-feeds/:id
func DeleteThreatFeed(c *gin.Context) {
	id := c.Param("id")
	if err := repositories.DeleteThreatFeed(id, tenantIDFromContext(c)); err != nil {
		c.JSON(404, gin.H{"error": "feed not found"})
		return
	}
	username, _ := c.Get("username")
	services.LogEvent("THREAT_FEED_DELETE", fmt.Sprintf("id=%s", id), fmt.Sprintf("%v", username))
	c.JSON(200, gin.H{"message": "deleted"})
}

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

	if err != nil && count == 0 {
		services.LogEvent("SYNC_THREAT_FEED_PARTIAL", errMsg, user)
		c.JSON(422, gin.H{"error": err.Error(), "count": 0})
		return
	}

	services.LogEvent("SYNC_THREAT_FEED", feed.Name, user)

	resp := gin.H{"message": "Feed Synced", "count": count}
	if err != nil {
		resp["warning"] = fmt.Sprintf("Partial sync: %d indicators imported, then: %v", count, err)
	}
	c.JSON(200, resp)
}
