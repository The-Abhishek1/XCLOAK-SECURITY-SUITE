package api

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/database"
)

type CorrelationRule struct {
	ID             int       `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Severity       string    `json:"severity"`
	RuleName       string    `json:"rule_name"`
	MitreTechnique string    `json:"mitre_technique"`
	AgentID        int       `json:"agent_id"`
	Action         string    `json:"action"`
	PlaybookID     int       `json:"playbook_id"`
	Enabled        bool      `json:"enabled"`
	MatchCount     int       `json:"match_count"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
}

func GetCorrelationRules(c *gin.Context) {
	rows, err := database.DB.Query(`
		SELECT id, name, description, severity, rule_name, mitre_technique,
		       agent_id, action, playbook_id, enabled, match_count, created_by,
		       created_at AT TIME ZONE 'UTC'
		FROM correlation_rules WHERE tenant_id=$1 ORDER BY created_at DESC
	`, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var rules []CorrelationRule
	for rows.Next() {
		var r CorrelationRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.Severity,
			&r.RuleName, &r.MitreTechnique, &r.AgentID, &r.Action,
			&r.PlaybookID, &r.Enabled, &r.MatchCount, &r.CreatedBy, &r.CreatedAt); err == nil {
			rules = append(rules, r)
		}
	}
	if rules == nil {
		rules = []CorrelationRule{}
	}
	c.JSON(200, rules)
}

func CreateCorrelationRule(c *gin.Context) {
	var r CorrelationRule
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	username, _ := c.Get("username")
	r.CreatedBy = fmt.Sprintf("%v", username)

	// AgentID==0 means "any agent" (matches suppression rules' convention) —
	// only validate ownership when a specific agent was named, otherwise a
	// caller could scope a rule to another tenant's agent.
	if r.AgentID != 0 && !agentOwnedBy404(c, strconv.Itoa(r.AgentID)) {
		return
	}

	err := database.DB.QueryRow(`
		INSERT INTO correlation_rules
		(name, description, severity, rule_name, mitre_technique,
		 agent_id, action, playbook_id, enabled, created_by, tenant_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,TRUE,$9,$10)
		RETURNING id, created_at AT TIME ZONE 'UTC'
	`, r.Name, r.Description, r.Severity, r.RuleName, r.MitreTechnique,
		r.AgentID, r.Action, r.PlaybookID, r.CreatedBy, tenantIDFromContext(c)).
		Scan(&r.ID, &r.CreatedAt)

	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, r)
}

func ToggleCorrelationRule(c *gin.Context) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	c.ShouldBindJSON(&body)
	_, err := database.DB.Exec(
		`UPDATE correlation_rules SET enabled=$1 WHERE id=$2 AND tenant_id=$3`, body.Enabled, c.Param("id"), tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "updated"})
}

func DeleteCorrelationRule(c *gin.Context) {
	_, err := database.DB.Exec(`DELETE FROM correlation_rules WHERE id=$1 AND tenant_id=$2`, c.Param("id"), tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "deleted"})
}

// GetAgentAuthLogs — GET /api/agents/:id/auth-logs
func GetAgentAuthLogs(c *gin.Context) {
	agentID := c.Param("id")
	if !agentOwnedBy404(c, agentID) {
		return
	}

	rows, err := database.DB.Query(`
		SELECT id, agent_id, log_source, log_message,
		       collected_at AT TIME ZONE 'UTC'
		FROM endpoint_logs
		WHERE agent_id = $1
		ORDER BY id DESC LIMIT 500
	`, agentID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type LogEntry struct {
		ID         int       `json:"id"`
		AgentID    int       `json:"agent_id"`
		LogSource  string    `json:"log_source"`
		LogMessage string    `json:"log_message"`
		CreatedAt  time.Time `json:"created_at"`
	}

	var logs []LogEntry
	for rows.Next() {
		var l LogEntry
		err := rows.Scan(&l.ID, &l.AgentID, &l.LogSource, &l.LogMessage, &l.CreatedAt)
		if err != nil {
			c.JSON(500, gin.H{"error": "scan: " + err.Error()})
			return
		}
		logs = append(logs, l)
	}
	if logs == nil {
		logs = []LogEntry{}
	}
	c.JSON(200, logs)
}
