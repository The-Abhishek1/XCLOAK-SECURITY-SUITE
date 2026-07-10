package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// ReceiveAuditEvents — POST /api/agents/audit-events  (agent auth)
// Called by the agent's auditd collector every 30 seconds with new execve events.
func ReceiveAuditEvents(c *gin.Context) {

	var events []models.AuditEvent
	if err := c.ShouldBindJSON(&events); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(events) == 0 {
		c.JSON(http.StatusOK, gin.H{"message": "no events"})
		return
	}

	if err := repositories.SaveAuditEvents(events); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Fire alerts for any threat-tagged events.
	for _, ev := range events {
		if ev.ThreatTag == "" {
			continue
		}
		services.CreateAlertFromAuditEvent(ev)
	}

	c.JSON(http.StatusOK, gin.H{"saved": len(events)})
}

// GetAuditEvents — GET /api/agents/:id/audit-events  (user auth)
// Returns the most recent audit events for an agent.
func GetAuditEvents(c *gin.Context) {

	agentID := c.Param("id")
	if !agentOwnedBy404(c, agentID) {
		return
	}

	limitStr := c.DefaultQuery("limit", "200")
	limit, _ := strconv.Atoi(limitStr)

	events, err := repositories.GetAuditEventsByAgent(agentID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, events)
}

// GetThreatAuditEvents — GET /api/audit-events/threats  (user auth)
// Returns all threat-tagged audit events across all agents — useful for
// the dashboard "Command Threats" widget.
func GetThreatAuditEvents(c *gin.Context) {

	limitStr := c.DefaultQuery("limit", "100")
	limit, _ := strconv.Atoi(limitStr)

	events, err := repositories.GetThreatAuditEvents(limit, tenantIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, events)
}
