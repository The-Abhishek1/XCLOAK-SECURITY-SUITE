package repositories

import (
	"encoding/json"
	"fmt"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func CreateTask(task models.AgentTask) error {
	payload := task.Payload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	_, err := database.DB.Exec(`
		INSERT INTO agent_tasks (agent_id, task_type, payload)
		VALUES ($1, $2, $3)
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
		INSERT INTO agent_tasks (agent_id, task_type, payload, status)
		VALUES ($1, $2, $3, 'pending_approval')
	`, task.AgentID, task.TaskType, payload)
	return err
}

// ApproveTask releases a pending_approval task for dispatch by flipping it
// to 'pending' — the agent will pick it up on its next poll. Only affects
// rows still in pending_approval, so approving an already-expired/rejected
// task is a no-op (returns 0 rows affected).
func ApproveTask(taskID int) (int64, error) {
	res, err := database.DB.Exec(`
		UPDATE agent_tasks SET status = 'pending'
		WHERE id = $1 AND status = 'pending_approval'
	`, taskID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RejectTask marks a pending_approval task as rejected so it's never
// dispatched to the agent.
func RejectTask(taskID int, reason string) (int64, error) {
	res, err := database.DB.Exec(`
		UPDATE agent_tasks
		SET status = 'rejected', result = $2, completed_at = NOW()
		WHERE id = $1 AND status = 'pending_approval'
	`, taskID, reason)
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

func CompleteTask(taskID int, result string) error {
	_, err := database.DB.Exec(`
		UPDATE agent_tasks
		SET status='completed', result=$1, completed_at=NOW()
		WHERE id=$2
	`, result, taskID)
	return err
}
