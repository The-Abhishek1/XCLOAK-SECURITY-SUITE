package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func CreatePlaybook(
	playbook models.Playbook,
) error {

	_, err := database.DB.Exec(`
		INSERT INTO playbooks
		(
			name,
			trigger_type,
			action_type,
			enabled
		)
		VALUES ($1,$2,$3,$4)
	`,
		playbook.Name,
		playbook.TriggerType,
		playbook.ActionType,
		playbook.Enabled,
	)

	return err
}

func GetPlaybooks() (
	[]models.Playbook,
	error,
) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			name,
			trigger_type,
			action_type,
			enabled,
			created_at
		FROM playbooks
		ORDER BY id DESC
	`)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var playbooks []models.Playbook

	for rows.Next() {

		var p models.Playbook

		err := rows.Scan(
			&p.ID,
			&p.Name,
			&p.TriggerType,
			&p.ActionType,
			&p.Enabled,
			&p.CreatedAt,
		)

		if err != nil {
			continue
		}

		playbooks = append(
			playbooks,
			p,
		)
	}

	return playbooks, nil
}

func GetEnabledPlaybooks() (
	[]models.Playbook,
	error,
) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			name,
			trigger_type,
			action_type,
			enabled,
			created_at
		FROM playbooks
		WHERE enabled=true
	`)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var playbooks []models.Playbook

	for rows.Next() {

		var p models.Playbook

		rows.Scan(
			&p.ID,
			&p.Name,
			&p.TriggerType,
			&p.ActionType,
			&p.Enabled,
			&p.CreatedAt,
		)

		playbooks = append(
			playbooks,
			p,
		)
	}

	return playbooks, nil
}
