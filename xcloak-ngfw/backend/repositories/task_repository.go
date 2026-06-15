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
