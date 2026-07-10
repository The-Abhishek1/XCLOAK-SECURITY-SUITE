package repositories

import (
	"errors"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// ErrPlaybookNotFound is returned by tenant-scoped mutations below when no
// row matches id+tenantID — covers both a nonexistent id and a real id
// belonging to another tenant.
var ErrPlaybookNotFound = errors.New("playbook not found")

// UpdatePlaybook updates name/trigger_type/action_type/enabled for a playbook.
func UpdatePlaybook(id int, p models.Playbook, tenantID int) error {

	tag, err := database.DB.Exec(`
		UPDATE playbooks
		SET name = $1, trigger_type = $2, action_type = $3, enabled = $4
		WHERE id = $5 AND tenant_id = $6
	`,
		p.Name,
		p.TriggerType,
		p.ActionType,
		p.Enabled,
		id,
		tenantID,
	)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrPlaybookNotFound
	}
	return nil
}

// DeletePlaybook removes a playbook and all of its actions (FK cascade or
// manual cleanup depending on schema — we delete actions first to be safe).
func DeletePlaybook(id int, tenantID int) error {

	tx, err := database.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`
		DELETE FROM playbook_actions
		WHERE playbook_id = $1 AND playbook_id IN (SELECT id FROM playbooks WHERE tenant_id = $2)
	`, id, tenantID); err != nil {
		return err
	}

	tag, err := tx.Exec(`DELETE FROM playbooks WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrPlaybookNotFound
	}

	return tx.Commit()
}

// SetPlaybookEnabled toggles the enabled flag.
func SetPlaybookEnabled(id int, enabled bool, tenantID int) error {

	tag, err := database.DB.Exec(`
		UPDATE playbooks SET enabled = $1 WHERE id = $2 AND tenant_id = $3
	`, enabled, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrPlaybookNotFound
	}
	return nil
}
