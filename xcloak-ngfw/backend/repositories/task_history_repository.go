package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// GetAgentTaskHistory returns all tasks (any status) for one agent, newest first.
func GetAgentTaskHistory(agentID string) ([]models.AgentTask, error) {
	rows, err := database.DB.Query(`
		SELECT
			id, agent_id, task_type,
			COALESCE(payload::text, '{}'),
			status,
			COALESCE(result, ''),
			created_at, completed_at
		FROM agent_tasks
		WHERE agent_id = $1
		ORDER BY id DESC
		LIMIT 200
	`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []models.AgentTask
	for rows.Next() {
		var t models.AgentTask
		var payloadStr, result string
		if err := rows.Scan(
			&t.ID, &t.AgentID, &t.TaskType, &payloadStr,
			&t.Status, &result, &t.CreatedAt, &t.CompletedAt,
		); err == nil {
			t.Payload = []byte(payloadStr)
			r := result
			t.Result = &r
			tasks = append(tasks, t)
		}
	}
	return tasks, nil
}

// GetTaskByID returns a single task — used to poll for script results.
func GetTaskByID(taskID string) (*models.AgentTask, error) {
	var t models.AgentTask
	var payloadStr, result string

	err := database.DB.QueryRow(`
		SELECT id, agent_id, task_type,
		       COALESCE(payload::text, '{}'),
		       status,
		       COALESCE(result, ''),
		       created_at, completed_at
		FROM agent_tasks WHERE id = $1
	`, taskID).Scan(
		&t.ID, &t.AgentID, &t.TaskType, &payloadStr,
		&t.Status, &result, &t.CreatedAt, &t.CompletedAt,
	)
	if err != nil {
		return nil, err
	}
	t.Payload = []byte(payloadStr)
	r := result
	t.Result = &r
	return &t, nil
}
