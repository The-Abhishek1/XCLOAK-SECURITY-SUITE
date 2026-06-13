package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

// CreateYaraRule — POST /api/yara/rules
func CreateYaraRule(c *gin.Context) {

	var rule models.YaraRule

	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := repositories.CreateYaraRule(rule); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	services.LogEvent("CREATE_YARA_RULE", rule.Name, "admin")

	c.JSON(200, gin.H{"message": "YARA Rule Created"})
}

// GetYaraRules — GET /api/yara/rules
// Dashboard calls this with RequireAuth (user JWT).
// Agents also call this with RequireAgentAuth to fetch rules to scan with —
// both middlewares populate the request the same way for this read-only route.
func GetYaraRules(c *gin.Context) {

	rules, err := repositories.GetYaraRules()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if rules == nil {
		rules = []models.YaraRule{}
	}

	c.JSON(200, rules)
}

// GetEnabledYaraRules — GET /api/yara/rules/enabled
// Lightweight endpoint for agents: only enabled rules, used before a scan.
func GetEnabledYaraRules(c *gin.Context) {

	rules, err := repositories.GetEnabledYaraRules()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if rules == nil {
		rules = []models.YaraRule{}
	}

	c.JSON(200, rules)
}

// UpdateYaraRule — PUT /api/yara/rules/:id
func UpdateYaraRule(c *gin.Context) {

	id := c.Param("id")

	var rule models.YaraRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := repositories.UpdateYaraRule(id, rule); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "YARA Rule Updated"})
}

// DeleteYaraRule — DELETE /api/yara/rules/:id
func DeleteYaraRule(c *gin.Context) {

	id := c.Param("id")

	if err := repositories.DeleteYaraRule(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "YARA Rule Deleted"})
}

// EnableYaraRule — PATCH /api/yara/rules/:id/enable
func EnableYaraRule(c *gin.Context) {
	toggleYaraRule(c, true)
}

// DisableYaraRule — PATCH /api/yara/rules/:id/disable
func DisableYaraRule(c *gin.Context) {
	toggleYaraRule(c, false)
}

func toggleYaraRule(c *gin.Context, enabled bool) {

	id := c.Param("id")

	if err := repositories.SetYaraRuleEnabled(id, enabled); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	msg := "YARA Rule Disabled"
	if enabled {
		msg = "YARA Rule Enabled"
	}

	c.JSON(200, gin.H{"message": msg})
}

// GetYaraMatches — GET /api/yara/matches
// Optional ?agent_id= query param to filter.
func GetYaraMatches(c *gin.Context) {

	agentID := c.Query("agent_id")

	matches, err := repositories.GetYaraMatches(agentID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if matches == nil {
		matches = []models.YaraMatch{}
	}

	c.JSON(200, matches)
}
