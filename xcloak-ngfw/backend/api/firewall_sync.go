package api

import (
	"fmt"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/services"
)

// SyncFirewallRules — POST /api/firewall/sync
// Dispatches all enabled rules to one or all online agents.
//
// Body (all optional):
//
//	{
//	  "agent_ids":    [1, 2],     // omit = all online agents
//	  "mode":         "replace",  // "replace" | "append" — default replace
//	  "manage_ip":    "10.0.0.1"  // XCloak server IP; always whitelisted
//	}
func SyncFirewallRules(c *gin.Context) {
	var body struct {
		AgentIDs []int  `json:"agent_ids"`
		Mode     string `json:"mode"`
		ManageIP string `json:"manage_ip"`
	}
	c.ShouldBindJSON(&body)

	// Fallback: use SERVER_IP env var or a sane default.
	if body.ManageIP == "" {
		body.ManageIP = os.Getenv("SERVER_IP")
	}
	if body.Mode == "" {
		body.Mode = "replace"
	}

	username, _ := c.Get("username")
	syncedBy := fmt.Sprintf("%v", username)

	results, err := services.SyncFirewallToAgents(
		body.AgentIDs,
		body.Mode,
		body.ManageIP,
		syncedBy,
	)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	dispatched := 0
	for _, r := range results {
		if r.Dispatched {
			dispatched++
		}
	}

	c.JSON(200, gin.H{
		"dispatched": dispatched,
		"total":      len(results),
		"results":    results,
		"message":    fmt.Sprintf("Dispatched to %d/%d agents", dispatched, len(results)),
	})
}

// GetFirewallSyncLog — GET /api/firewall/sync/log?agent_id=1
func GetFirewallSyncLog(c *gin.Context) {
	agentID, _ := strconv.Atoi(c.Query("agent_id"))

	logs, err := services.GetFirewallSyncLog(agentID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, logs)
}
