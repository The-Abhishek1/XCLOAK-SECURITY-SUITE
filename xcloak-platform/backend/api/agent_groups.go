package api

import (
	"encoding/json"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
)

// AgentGroup is the JSON shape returned by group list/create endpoints.
type AgentGroup struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	AgentCount  int    `json:"agent_count"`
	CreatedAt   string `json:"created_at"`
}

// ListAgentGroups — GET /api/agent-groups
func ListAgentGroups(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	rows, err := database.DB.Query(`
		SELECT g.id, g.name, COALESCE(g.description,''),
		       COUNT(gm.agent_id) AS agent_count,
		       g.created_at::text
		FROM agent_groups g
		LEFT JOIN agent_group_members gm ON gm.group_id = g.id
		WHERE g.tenant_id = $1
		GROUP BY g.id, g.name, g.description, g.created_at
		ORDER BY g.name
	`, tenantID)
	if err != nil {
		c.JSON(200, []AgentGroup{})
		return
	}
	defer rows.Close()
	groups := []AgentGroup{}
	for rows.Next() {
		var g AgentGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.AgentCount, &g.CreatedAt); err == nil {
			groups = append(groups, g)
		}
	}
	if groups == nil {
		groups = []AgentGroup{}
	}
	c.JSON(200, groups)
}

// CreateAgentGroup — POST /api/agent-groups
func CreateAgentGroup(c *gin.Context) {
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(400, gin.H{"error": "name required"})
		return
	}
	tenantID := tenantIDFromContext(c)
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO agent_groups (name, description, tenant_id)
		VALUES ($1, $2, $3) RETURNING id
	`, body.Name, body.Description, tenantID).Scan(&id)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to create group"})
		return
	}
	c.JSON(201, gin.H{"id": id, "name": body.Name})
}

// DeleteAgentGroup — DELETE /api/agent-groups/:id
func DeleteAgentGroup(c *gin.Context) {
	id := c.Param("id")
	tenantID := tenantIDFromContext(c)
	_, err := database.DB.Exec(
		`DELETE FROM agent_groups WHERE id = $1 AND tenant_id = $2`, id, tenantID,
	)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to delete group"})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

// BulkAgentAction — POST /api/agents/bulk
// Dispatches a task to multiple agents at once.
func BulkAgentAction(c *gin.Context) {
	var body struct {
		AgentIDs []int          `json:"agent_ids"`
		Action   string         `json:"action"`
		Payload  map[string]any `json:"payload"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.AgentIDs) == 0 || body.Action == "" {
		c.JSON(400, gin.H{"error": "agent_ids and action required"})
		return
	}
	if body.Payload == nil {
		body.Payload = map[string]any{}
	}
	payloadJSON, _ := json.Marshal(body.Payload)

	ok := 0
	for _, agentID := range body.AgentIDs {
		_, err := database.DB.Exec(`
			INSERT INTO tasks (agent_id, task_type, payload, status)
			VALUES ($1, $2, $3, 'pending')
		`, agentID, body.Action, string(payloadJSON))
		if err == nil {
			ok++
		}
	}
	c.JSON(200, gin.H{"dispatched": ok, "total": len(body.AgentIDs)})
}
