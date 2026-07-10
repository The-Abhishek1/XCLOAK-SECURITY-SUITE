package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/services"
)

// ReceiveConnectEvents — POST /api/agents/connect-events  (agent auth)
// Called by the agent's eBPF module with real-time outbound-connection
// events (kprobe on tcp_v4_connect) — append-only, distinct from
// /api/agents/connections' destructive snapshot-replace semantics.
func ReceiveConnectEvents(c *gin.Context) {

	var events []models.ConnectEvent
	if err := c.ShouldBindJSON(&events); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(events) == 0 {
		c.JSON(http.StatusOK, gin.H{"message": "no events"})
		return
	}

	if err := services.SaveConnectEvents(events); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"saved": len(events)})
}

// GetConnectEvents — GET /api/agents/:id/connect-events  (user auth)
func GetConnectEvents(c *gin.Context) {

	agentID := c.Param("id")
	if !agentOwnedBy404(c, agentID) {
		return
	}

	id, err := strconv.Atoi(agentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent id"})
		return
	}

	events, err := services.GetConnectEvents(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, events)
}
