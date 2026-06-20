package api

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/services"
)

// ── Suppression Rules ─────────────────────────────────────────

func GetSuppressionRules(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	rules, err := services.GetSuppressionRules(tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if rules == nil {
		rules = []services.SuppressionRule{}
	}
	c.JSON(200, gin.H{
		"rules": rules,
		"stats": services.GetSuppressionStats(tenantID),
	})
}

func CreateSuppressionRule(c *gin.Context) {
	var r services.SuppressionRule
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	username, _ := c.Get("username")
	r.CreatedBy = fmt.Sprintf("%v", username)
	if r.WindowMinutes == 0 {
		r.WindowMinutes = 60
	}

	created, err := services.CreateSuppressionRule(r, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, created)
}

func DeleteSuppressionRule(c *gin.Context) {
	if err := services.DeleteSuppressionRule(c.Param("id"), tenantIDFromContext(c)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "deleted"})
}

func ToggleSuppressionRule(c *gin.Context) {
	var body struct{ Enabled bool `json:"enabled"` }
	c.ShouldBindJSON(&body)
	if err := services.ToggleSuppressionRule(c.Param("id"), body.Enabled, tenantIDFromContext(c)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "updated"})
}

// ── GeoIP ─────────────────────────────────────────────────────

func GetGeoIP(c *gin.Context) {
	ip := c.Param("ip")
	if ip == "" {
		c.JSON(400, gin.H{"error": "ip required"})
		return
	}
	result, err := services.LookupGeoIP(ip)
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

func GetAgentGeoStats(c *gin.Context) {
	agentID := c.Param("id")
	if !agentOwnedBy404(c, agentID) {
		return
	}
	results, err := services.GetTopExternalCountries(agentID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if results == nil {
		results = []map[string]interface{}{}
	}
	c.JSON(200, results)
}

func EnrichAgentConnections(c *gin.Context) {
	agentID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid agent id"})
		return
	}
	if !agentOwnedBy404(c, c.Param("id")) {
		return
	}
	go services.EnrichConnections(agentID)
	c.JSON(200, gin.H{"message": "GeoIP enrichment started in background"})
}

// ── Agent Health ──────────────────────────────────────────────

func GetAgentHealthScores(c *gin.Context) {
	scores, err := services.GetAgentHealthScores(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if scores == nil {
		scores = []services.AgentHealth{}
	}
	c.JSON(200, scores)
}

func GetAgentHealth(c *gin.Context) {
	agentID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid agent id"})
		return
	}
	if !agentOwnedBy404(c, c.Param("id")) {
		return
	}
	h := services.GetAgentHealthByID(agentID)
	c.JSON(200, h)
}

func RefreshAgentHealth(c *gin.Context) {
	go services.ComputeAgentHealth()
	c.JSON(200, gin.H{"message": "Health computation triggered"})
}

// ── IOC Auto-Block ────────────────────────────────────────────

func GetIOCBlocks(c *gin.Context) {
	blocks, err := services.GetIOCBlocks(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if blocks == nil {
		blocks = []map[string]interface{}{}
	}
	c.JSON(200, blocks)
}
