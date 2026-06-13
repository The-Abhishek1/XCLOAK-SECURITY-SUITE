package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// UpdatePlaybook updates name/trigger_type/action_type/enabled for a playbook.
func UpdatePlaybook(id int, p models.Playbook) error {

	_, err := database.DB.Exec(`
		UPDATE playbooks
		SET name = $1, trigger_type = $2, action_type = $3, enabled = $4
		WHERE id = $5
	`,
		p.Name,
		p.TriggerType,
		p.ActionType,
		p.Enabled,
		id,
	)

	return err
}

// DeletePlaybook removes a playbook and all of its actions (FK cascade or
// manual cleanup depending on schema — we delete actions first to be safe).
func DeletePlaybook(id int) error {

	tx, err := database.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM playbook_actions WHERE playbook_id = $1`, id); err != nil {
		return err
	}

	if _, err := tx.Exec(`DELETE FROM playbooks WHERE id = $1`, id); err != nil {
		return err
	}

	return tx.Commit()
}

// SetPlaybookEnabled toggles the enabled flag.
func SetPlaybookEnabled(id int, enabled bool) error {

	_, err := database.DB.Exec(`
		UPDATE playbooks SET enabled = $1 WHERE id = $2
	`, enabled, id)

	return err
}
