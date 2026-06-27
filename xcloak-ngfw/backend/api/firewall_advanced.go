package api

import (
	"fmt"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

// GetFirewallGroups — GET /api/firewall/groups
func GetFirewallGroups(c *gin.Context) {
	groups, err := repositories.GetFirewallGroups(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if groups == nil {
		groups = []map[string]interface{}{}
	}
	c.JSON(200, groups)
}

// GetFirewallStats — GET /api/firewall/stats
func GetFirewallStats(c *gin.Context) {
	stats, err := repositories.GetFirewallStats(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, stats)
}

// GetFirewallConflicts — GET /api/firewall/conflicts
func GetFirewallConflicts(c *gin.Context) {
	conflicts, err := services.DetectFirewallConflicts(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, conflicts)
}

// ReceiveFirewallHits — POST /api/agents/firewall-hits
// Agents submit per-rule packet counters periodically.
func ReceiveFirewallHits(c *gin.Context) {
	agentIDVal, _ := c.Get("agent_id")
	agentID := 0
	switch v := agentIDVal.(type) {
	case int:
		agentID = v
	case float64:
		agentID = int(v)
	}
	tenantID := tenantIDFromContext(c)

	var body struct {
		Hits []repositories.FirewallHit `json:"hits"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.Hits) == 0 {
		c.JSON(400, gin.H{"error": "hits array required"})
		return
	}

	repositories.RecordFirewallHits(agentID, tenantID, body.Hits)
	c.JSON(200, gin.H{"recorded": fmt.Sprintf("%d", len(body.Hits))})
}
