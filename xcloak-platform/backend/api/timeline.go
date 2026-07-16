package api

import (
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// GetTenantTimeline returns filtered timeline events for the caller's tenant.
func GetTenantTimeline(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	agentID, _ := strconv.Atoi(c.Query("agent_id"))

	var from, to time.Time
	if f := c.Query("from"); f != "" {
		from, _ = time.Parse(time.RFC3339, f)
	}
	if t := c.Query("to"); t != "" {
		to, _ = time.Parse(time.RFC3339, t)
	}

	var eventTypes []string
	if et := c.Query("event_types"); et != "" {
		for _, s := range strings.Split(et, ",") {
			if s = strings.TrimSpace(s); s != "" {
				eventTypes = append(eventTypes, s)
			}
		}
	}

	filter := services.TimelineFilter{
		EventTypes: eventTypes,
		Severity:   c.Query("severity"),
		AgentID:    agentID,
		Search:     c.Query("search"),
		From:       from,
		To:         to,
		Limit:      limit,
		Offset:     offset,
	}

	events, err := services.GetTenantTimeline(tenantIDFromContext(c), filter)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, events)
}

// GetTimelineStats returns per-event-type counts over the last 7 days.
func GetTimelineStats(c *gin.Context) {
	counts, err := services.GetTenantTimelineStats(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, counts)
}

// GetAgentTimeline returns timeline events for a single agent.
func GetAgentTimeline(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid agent id"})
		return
	}

	if _, err := repositories.GetAgentByID(c.Param("id"), tenantIDFromContext(c)); err != nil {
		c.JSON(404, gin.H{"error": "agent not found"})
		return
	}

	timeline, err := services.GetAgentTimeline(id)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, timeline)
}
