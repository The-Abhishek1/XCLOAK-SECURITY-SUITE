package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func CreatePlaybookExecution(execution models.PlaybookExecution) error {
	_, err := database.DB.Exec(`
		INSERT INTO playbook_executions
		(playbook_id, agent_id, alert_rule, action_type, status, error_detail, task_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
	`,
		execution.PlaybookID,
		execution.AgentID,
		execution.AlertRule,
		execution.ActionType,
		execution.Status,
		execution.ErrorDetail,
		execution.TaskID,
	)
	return err
}

func GetPlaybookExecutions() ([]models.PlaybookExecution, error) {
	rows, err := database.DB.Query(`
		SELECT
			id, playbook_id, agent_id, alert_rule, action_type, status,
			COALESCE(error_detail,''), COALESCE(task_id,0), created_at
		FROM playbook_executions
		ORDER BY id DESC
		LIMIT 200
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var executions []models.PlaybookExecution
	for rows.Next() {
		var e models.PlaybookExecution
		if err := rows.Scan(
			&e.ID, &e.PlaybookID, &e.AgentID, &e.AlertRule,
			&e.ActionType, &e.Status, &e.ErrorDetail, &e.TaskID, &e.CreatedAt,
		); err == nil {
			executions = append(executions, e)
		}
	}
	return executions, nil
}
