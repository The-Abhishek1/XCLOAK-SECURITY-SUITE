package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func GetPlaybookActions(
	playbookID int,
) ([]models.PlaybookAction, error) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			playbook_id,
			step_order,
			action_type,
			payload,
			created_at
		FROM playbook_actions
		WHERE playbook_id=$1
		ORDER BY step_order
	`,
		playbookID,
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var actions []models.PlaybookAction

	for rows.Next() {

		var action models.PlaybookAction

		rows.Scan(
			&action.ID,
			&action.PlaybookID,
			&action.StepOrder,
			&action.ActionType,
			&action.Payload,
			&action.CreatedAt,
		)

		actions = append(
			actions,
			action,
		)
	}

	return actions, nil
}

func CreatePlaybookAction(
	action models.PlaybookAction,
) error {

	_, err := database.DB.Exec(`
		INSERT INTO playbook_actions
		(
			playbook_id,
			step_order,
			action_type,
			payload
		)
		VALUES ($1,$2,$3,$4)
	`,
		action.PlaybookID,
		action.StepOrder,
		action.ActionType,
		action.Payload,
	)

	return err
}

func GetPlaybookActionsByPlaybookID(
	playbookID string,
) ([]models.PlaybookAction, error) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			playbook_id,
			step_order,
			action_type,
			payload,
			created_at
		FROM playbook_actions
		WHERE playbook_id=$1
		ORDER BY step_order
	`,
		playbookID,
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var actions []models.PlaybookAction

	for rows.Next() {

		var action models.PlaybookAction

		err := rows.Scan(
			&action.ID,
			&action.PlaybookID,
			&action.StepOrder,
			&action.ActionType,
			&action.Payload,
			&action.CreatedAt,
		)

		if err != nil {
			continue
		}

		actions = append(
			actions,
			action,
		)
	}

	return actions, nil
}

func DeletePlaybookAction(
	id string,
) error {

	_, err := database.DB.Exec(`
		DELETE FROM playbook_actions
		WHERE id=$1
	`,
		id,
	)

	return err
}
