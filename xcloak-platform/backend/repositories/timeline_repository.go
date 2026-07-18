package repositories

import (
	"xcloak-platform/database"
	"xcloak-platform/models"
)

func GetAlertsByAgentID(
	agentID int,
) ([]models.Alert, error) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			agent_id,
			severity,
			rule_name,
			log_message,
			created_at,
			fingerprint,
			mitre_tactic,
			mitre_technique,
			mitre_name
		FROM alerts
		WHERE agent_id = $1
		ORDER BY created_at
	`,
		agentID,
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	alerts := []models.Alert{}

	for rows.Next() {

		var alert models.Alert

		err := rows.Scan(
			&alert.ID,
			&alert.AgentID,
			&alert.Severity,
			&alert.RuleName,
			&alert.LogMessage,
			&alert.CreatedAt,
			&alert.Fingerprint,
			&alert.MitreTactic,
			&alert.MitreTechnique,
			&alert.MitreName,
		)

		if err != nil {
			continue
		}

		alerts = append(
			alerts,
			alert,
		)
	}

	return alerts, nil
}

func GetIncidentsByAgentID(
	agentID int,
) ([]models.Incident, error) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			agent_id,
			title,
			severity,
			status,
			description,
			created_at
		FROM incidents
		WHERE agent_id = $1
		ORDER BY created_at
	`,
		agentID,
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	incidents := []models.Incident{}

	for rows.Next() {

		var incident models.Incident

		err := rows.Scan(
			&incident.ID,
			&incident.AgentID,
			&incident.Title,
			&incident.Severity,
			&incident.Status,
			&incident.Description,
			&incident.CreatedAt,
		)

		if err != nil {
			continue
		}

		incidents = append(
			incidents,
			incident,
		)
	}

	return incidents, nil
}

func GetPlaybookExecutionsByAgentID(
	agentID int,
) ([]models.PlaybookExecution, error) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			playbook_id,
			agent_id,
			alert_rule,
			action_type,
			status,
			created_at
		FROM playbook_executions
		WHERE agent_id = $1
		ORDER BY created_at
	`,
		agentID,
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	executions := []models.PlaybookExecution{}

	for rows.Next() {

		var execution models.PlaybookExecution

		err := rows.Scan(
			&execution.ID,
			&execution.PlaybookID,
			&execution.AgentID,
			&execution.AlertRule,
			&execution.ActionType,
			&execution.Status,
			&execution.CreatedAt,
		)

		if err != nil {
			continue
		}

		executions = append(
			executions,
			execution,
		)
	}

	return executions, nil
}
