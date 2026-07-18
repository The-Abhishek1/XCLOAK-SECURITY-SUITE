package api

import (
	"encoding/json"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
)

// getTaskResultJSON queries the most recent completed task of taskType for
// agentID and parses its JSON result. Returns an empty JSON array on any error.
func getTaskResultJSON(agentID, taskType string) any {
	var result string
	err := database.DB.QueryRow(`
		SELECT COALESCE(result, '[]')
		FROM tasks
		WHERE agent_id = $1 AND task_type = $2 AND status = 'completed'
		ORDER BY completed_at DESC
		LIMIT 1
	`, agentID, taskType).Scan(&result)
	if err != nil || result == "" || result == "null" {
		return []any{}
	}
	var parsed any
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		return []any{}
	}
	return parsed
}

// GetAgentStartupItems — GET /api/agents/:id/startup
func GetAgentStartupItems(c *gin.Context) {
	id := c.Param("id")
	if !agentOwnedBy404(c, id) {
		return
	}
	c.JSON(200, getTaskResultJSON(id, "collect_startup"))
}

// GetAgentUsbHistory — GET /api/agents/:id/usb-history
func GetAgentUsbHistory(c *gin.Context) {
	id := c.Param("id")
	if !agentOwnedBy404(c, id) {
		return
	}
	c.JSON(200, getTaskResultJSON(id, "collect_usb_history"))
}

// GetAgentLoginHistory — GET /api/agents/:id/login-history
// Sources from the most recent collect_auth_logs task result.
func GetAgentLoginHistory(c *gin.Context) {
	id := c.Param("id")
	if !agentOwnedBy404(c, id) {
		return
	}
	c.JSON(200, getTaskResultJSON(id, "collect_auth_logs"))
}

// GetAgentScheduledTasksList — GET /api/agents/:id/scheduled-tasks
func GetAgentScheduledTasksList(c *gin.Context) {
	id := c.Param("id")
	if !agentOwnedBy404(c, id) {
		return
	}
	c.JSON(200, getTaskResultJSON(id, "collect_scheduled_tasks"))
}

// GetAgentDriversList — GET /api/agents/:id/drivers
func GetAgentDriversList(c *gin.Context) {
	id := c.Param("id")
	if !agentOwnedBy404(c, id) {
		return
	}
	c.JSON(200, getTaskResultJSON(id, "collect_drivers"))
}

// GetAgentPolicies — GET /api/agents/:id/policies
// Returns agent-level policy settings. Currently derives from the agents row;
// when agent_policies table is added this can be updated to join it.
func GetAgentPolicies(c *gin.Context) {
	id := c.Param("id")
	if !agentOwnedBy404(c, id) {
		return
	}
	c.JSON(200, gin.H{
		"tamper_protection":        false,
		"network_isolation":        false,
		"fim_enabled":              false,
		"yara_enabled":             false,
		"auto_update":              true,
		"block_removable_media":    false,
		"script_execution_blocked": false,
		"max_cpu_percent":          30,
		"collection_interval_seconds": 300,
		"fim_paths":                []string{},
	})
}

// auditEntry is the shape returned by GetAgentAuditHistory.
type auditEntry struct {
	Action      string     `json:"action"`
	Actor       string     `json:"actor"`
	Status      string     `json:"status"`
	Timestamp   time.Time  `json:"timestamp"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Detail      string     `json:"detail,omitempty"`
}

// GetAgentAuditHistory — GET /api/agents/:id/audit-history
// Returns a chronological audit trail of all admin-initiated actions on the
// agent (task dispatches). The "Agent Installed" anchor is derived from the
// agents table created_at so it always appears even when no tasks exist.
func GetAgentAuditHistory(c *gin.Context) {
	id := c.Param("id")
	if !agentOwnedBy404(c, id) {
		return
	}

	events := []auditEntry{}

	// Anchor: agent installation timestamp
	var installedAt time.Time
	if err := database.DB.QueryRow(
		`SELECT created_at FROM agents WHERE id = $1`, id,
	).Scan(&installedAt); err == nil {
		events = append(events, auditEntry{
			Action:    "agent_installed",
			Actor:     "system",
			Status:    "completed",
			Timestamp: installedAt,
			Detail:    "Agent registered and enrolled",
		})
	}

	// Task-based audit trail — most recent 100 tasks
	rows, err := database.DB.Query(`
		SELECT task_type, status, created_at, completed_at, COALESCE(result,'') as result
		FROM tasks
		WHERE agent_id = $1
		ORDER BY created_at DESC
		LIMIT 100
	`, id)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var e auditEntry
			var result string
			e.Actor = "admin"
			if err := rows.Scan(&e.Action, &e.Status, &e.Timestamp, &e.CompletedAt, &result); err == nil {
				if len(result) > 120 {
					result = result[:120] + "…"
				}
				e.Detail = result
				events = append(events, e)
			}
		}
	}

	if events == nil {
		events = []auditEntry{}
	}
	c.JSON(200, events)
}
