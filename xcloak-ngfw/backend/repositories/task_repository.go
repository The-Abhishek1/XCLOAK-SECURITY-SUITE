package repositories

import (
	"encoding/json"
	"fmt"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// CreateTask inserts a task with tenant_id resolved from the owning agent —
// same pattern as CreateAlert.
func CreateTask(task models.AgentTask) error {
	payload := task.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	_, err := database.DB.Exec(`
		INSERT INTO agent_tasks (agent_id, task_type, payload, tenant_id)
		VALUES ($1, $2, $3, (SELECT tenant_id FROM agents WHERE id = $1))
	`, task.AgentID, task.TaskType, payload)
	return err
}

// CreateTaskPendingApproval inserts a task with status='pending_approval'
// instead of the default 'pending' — the agent's GetPendingTasks query only
// looks at status='pending', so the agent never sees it until an admin
// approves it via ApproveTask.
func CreateTaskPendingApproval(task models.AgentTask) error {
	payload := task.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	_, err := database.DB.Exec(`
		INSERT INTO agent_tasks (agent_id, task_type, payload, status, tenant_id)
		VALUES ($1, $2, $3, 'pending_approval', (SELECT tenant_id FROM agents WHERE id = $1))
	`, task.AgentID, task.TaskType, payload)
	return err
}

// ApproveTask releases a pending_approval task for dispatch by flipping it
// to 'pending' — the agent will pick it up on its next poll. Scoped to
// tenantID so an admin can't approve/release another tenant's destructive
// action. Only affects rows still in pending_approval, so approving an
// already-expired/rejected/wrong-tenant task is a no-op (0 rows affected).
func ApproveTask(taskID int, tenantID int) (int64, error) {
	res, err := database.DB.Exec(`
		UPDATE agent_tasks SET status = 'pending'
		WHERE id = $1 AND status = 'pending_approval' AND tenant_id = $2
	`, taskID, tenantID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RejectTask marks a pending_approval task as rejected so it's never
// dispatched to the agent. Scoped to tenantID for the same reason as
// ApproveTask.
func RejectTask(taskID int, reason string, tenantID int) (int64, error) {
	res, err := database.DB.Exec(`
		UPDATE agent_tasks
		SET status = 'rejected', result = $2, completed_at = NOW()
		WHERE id = $1 AND status = 'pending_approval' AND tenant_id = $3
	`, taskID, reason, tenantID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func GetPendingTasks(agentID string) ([]models.AgentTask, error) {
	rows, err := database.DB.Query(`
		SELECT
			id,
			agent_id,
			task_type,
			COALESCE(payload, '{}')::text,
			status,
			result,
			created_at,
			completed_at
		FROM agent_tasks
		WHERE agent_id = $1
		AND status = 'pending'
		ORDER BY created_at
	`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []models.AgentTask
	for rows.Next() {
		var task models.AgentTask
		var payloadStr string
		err := rows.Scan(
			&task.ID,
			&task.AgentID,
			&task.TaskType,
			&payloadStr,
			&task.Status,
			&task.Result,
			&task.CreatedAt,
			&task.CompletedAt,
		)
		if err != nil {
			fmt.Println("Error scanning task row:", err)
			continue
		}
		if payloadStr == "" || payloadStr == "null" {
			payloadStr = "{}"
		}
		task.Payload = json.RawMessage(payloadStr)
		tasks = append(tasks, task)
	}
	return tasks, nil
}

func MarkTaskRunning(taskID int) error {
	_, err := database.DB.Exec(`
		UPDATE agent_tasks SET status = 'running' WHERE id = $1
	`, taskID)
	return err
}

// CompleteTask marks a task completed, scoped to agentID — without this,
// any agent's bearer token could submit a fabricated result for any other
// agent's task (including destructive SOAR actions), since RequireAgentAuth
// only proves the token is valid for SOME agent, not that it owns taskID.
func CompleteTask(taskID int, result string, agentID int) error {
	tag, err := database.DB.Exec(`
		UPDATE agent_tasks
		SET status='completed', result=$1, completed_at=NOW()
		WHERE id=$2 AND agent_id=$3
	`, result, taskID, agentID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return fmt.Errorf("task not found")
	}
	return nil
}
