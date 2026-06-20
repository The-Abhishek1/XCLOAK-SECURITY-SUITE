package repositories

import (
	"errors"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// ErrPlaybookActionNotFound is returned by tenant-scoped mutations below
// when no row matches id+tenantID.
var ErrPlaybookActionNotFound = errors.New("playbook action not found")

// GetPlaybookActions is used internally by the SOAR engine, where
// playbookID was already resolved from a tenant-filtered playbook list
// (GetEnabledPlaybooksForAgent) — no further tenant check needed here.
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

		// FIX: unchecked Scan error meant a row with a NULL step_order
		// (column is nullable, no default) silently produced a zero-value
		// PlaybookAction{} with empty ActionType instead of erroring.
		if err := rows.Scan(
			&action.ID,
			&action.PlaybookID,
			&action.StepOrder,
			&action.ActionType,
			&action.Payload,
			&action.CreatedAt,
		); err != nil {
			continue
		}

		actions = append(
			actions,
			action,
		)
	}

	return actions, nil
}

func CreatePlaybookAction(
	action models.PlaybookAction,
	tenantID int,
) error {

	_, err := database.DB.Exec(`
		INSERT INTO playbook_actions
		(
			playbook_id,
			step_order,
			action_type,
			payload,
			tenant_id
		)
		VALUES ($1,$2,$3,$4,$5)
	`,
		action.PlaybookID,
		action.StepOrder,
		action.ActionType,
		action.Payload,
		tenantID,
	)

	return err
}

// GetPlaybookActionsByPlaybookID is the user-facing path (called with a
// playbook_id straight from a URL param) — filters by tenant_id directly
// since playbook_actions carries its own tenant_id column.
func GetPlaybookActionsByPlaybookID(
	playbookID string,
	tenantID int,
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
		WHERE playbook_id=$1 AND tenant_id=$2
		ORDER BY step_order
	`,
		playbookID,
		tenantID,
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
	tenantID int,
) error {

	tag, err := database.DB.Exec(`
		DELETE FROM playbook_actions
		WHERE id=$1 AND tenant_id=$2
	`,
		id,
		tenantID,
	)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrPlaybookActionNotFound
	}
	return nil
}
