package api

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/database"
	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

type pendingApprovalRow struct {
	ID        int    `json:"id"`
	AgentID   int    `json:"agent_id"`
	Hostname  string `json:"hostname"`
	TaskType  string `json:"task_type"`
	Payload   string `json:"payload"`
	CreatedAt string `json:"created_at"`
}

// GetPendingApprovalTasks — GET /api/tasks/pending-approval
// Lists destructive SOAR actions an enabled playbook tried to auto-dispatch,
// held for human review before the agent can pick them up.
func GetPendingApprovalTasks(c *gin.Context) {
	rows, err := database.DB.Query(`
		SELECT t.id, t.agent_id, COALESCE(a.hostname, ''), t.task_type,
		       COALESCE(t.payload::text, '{}'), t.created_at
		FROM agent_tasks t
		LEFT JOIN agents a ON a.id = t.agent_id
		WHERE t.status = 'pending_approval'
		ORDER BY t.created_at DESC
	`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var out []pendingApprovalRow
	for rows.Next() {
		var r pendingApprovalRow
		if err := rows.Scan(&r.ID, &r.AgentID, &r.Hostname, &r.TaskType, &r.Payload, &r.CreatedAt); err == nil {
			out = append(out, r)
		}
	}
	if out == nil {
		out = []pendingApprovalRow{}
	}
	c.JSON(200, out)
}

// ApproveTask — POST /api/tasks/:id/approve
func ApproveTask(c *gin.Context) {
	taskID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid task id"})
		return
	}

	n, err := repositories.ApproveTask(taskID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if n == 0 {
		c.JSON(409, gin.H{"error": "task is not awaiting approval (already approved, rejected, or expired)"})
		return
	}

	username, _ := c.Get("username")
	user := fmt.Sprintf("%v", username)
	services.LogEvent("SOAR_ACTION_APPROVED", fmt.Sprintf("task #%d approved by %s", taskID, user), user)

	c.JSON(200, gin.H{"message": "task approved — agent will pick it up on next poll"})
}

// RejectTask — POST /api/tasks/:id/reject
// Body (optional): { "reason": "false positive, alert was benign" }
func RejectTask(c *gin.Context) {
	taskID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid task id"})
		return
	}

	var body struct {
		Reason string `json:"reason"`
	}
	c.ShouldBindJSON(&body)
	if body.Reason == "" {
		body.Reason = "rejected by analyst"
	}

	n, err := repositories.RejectTask(taskID, body.Reason)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if n == 0 {
		c.JSON(409, gin.H{"error": "task is not awaiting approval (already approved, rejected, or expired)"})
		return
	}

	username, _ := c.Get("username")
	user := fmt.Sprintf("%v", username)
	services.LogEvent("SOAR_ACTION_REJECTED",
		fmt.Sprintf("task #%d rejected by %s: %s", taskID, user, body.Reason), user)

	c.JSON(200, gin.H{"message": "task rejected"})
}
