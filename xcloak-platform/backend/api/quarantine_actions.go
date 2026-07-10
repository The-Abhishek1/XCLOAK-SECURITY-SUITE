package api

import (
	"encoding/json"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// ReleaseQuarantinedFile — DELETE /api/quarantine/:id
// Body: { "restore": true } — if true, dispatches restore task to agent.
func ReleaseQuarantinedFile(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid id"})
		return
	}

	var agentID int
	var originalPath, quarantinePath string
	err = database.DB.QueryRow(`
		SELECT agent_id, original_path, quarantine_path
		FROM quarantined_files WHERE id=$1 AND tenant_id=$2
	`, id, tenantIDFromContext(c)).Scan(&agentID, &originalPath, &quarantinePath)

	if err != nil {
		c.JSON(404, gin.H{"error": "quarantine record not found"})
		return
	}

	var body struct {
		Restore bool `json:"restore"`
	}
	c.ShouldBindJSON(&body)

	// Dispatch restore task to the agent.
	if body.Restore && agentID > 0 {
		payload, _ := json.Marshal(map[string]string{
			"quarantine_path": quarantinePath,
			"restore_path":    originalPath,
		})
		repositories.CreateTask(models.AgentTask{
			AgentID:  agentID,
			TaskType: "restore_file",
			Payload:  payload,
		})
	}

	_, err = database.DB.Exec(`DELETE FROM quarantined_files WHERE id=$1 AND tenant_id=$2`, id, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	username, _ := c.Get("username")
	user := "admin"
	if username != nil {
		user = username.(string)
	}
	action := "DELETE_QUARANTINE"
	if body.Restore {
		action = "RELEASE_QUARANTINE"
	}
	services.LogEvent(action, originalPath+" (agent #"+strconv.Itoa(agentID)+")", user)

	c.JSON(200, gin.H{
		"message":            "quarantine record removed",
		"restore_dispatched": body.Restore,
	})
}

// GetQuarantineStats — GET /api/quarantine/stats
func GetQuarantineStats(c *gin.Context) {
	var total, affectedAgents int
	database.DB.QueryRow(
		`SELECT COUNT(*), COUNT(DISTINCT agent_id) FROM quarantined_files WHERE tenant_id=$1`,
		tenantIDFromContext(c),
	).Scan(&total, &affectedAgents)
	c.JSON(200, gin.H{"total_files": total, "affected_agents": affectedAgents})
}
