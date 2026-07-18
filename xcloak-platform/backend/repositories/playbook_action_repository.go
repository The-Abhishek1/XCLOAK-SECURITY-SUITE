package repositories

import (
	"errors"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

var ErrPlaybookActionNotFound = errors.New("playbook action not found")

// GetPlaybookActions is used internally by the SOAR engine — playbookID was
// already resolved from a tenant-filtered playbook, so no extra tenant check.
func GetPlaybookActions(playbookID int) ([]models.PlaybookAction, error) {
	rows, err := database.DB.Query(`
		SELECT
			id, playbook_id, step_order, action_type, payload,
			condition_expr, max_retries, retry_delay_secs, run_parallel, timeout_seconds,
			created_at,
			COALESCE(step_name,''), COALESCE(goto_on_success,''),
			COALESCE(goto_on_failure,''), COALESCE(stop_on_failure,FALSE),
			COALESCE(loop_over,'')
		FROM playbook_actions
		WHERE playbook_id = $1
		ORDER BY step_order, id
	`, playbookID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	actions := []models.PlaybookAction{}
	for rows.Next() {
		var a models.PlaybookAction
		if err := rows.Scan(
			&a.ID, &a.PlaybookID, &a.StepOrder, &a.ActionType, &a.Payload,
			&a.ConditionExpr, &a.MaxRetries, &a.RetryDelaySecs, &a.RunParallel, &a.TimeoutSeconds,
			&a.CreatedAt,
			&a.StepName, &a.GotoOnSuccess, &a.GotoOnFailure, &a.StopOnFailure, &a.LoopOver,
		); err != nil {
			continue
		}
		actions = append(actions, a)
	}
	return actions, nil
}

// GetPlaybookActionsByPlaybookID is the user-facing path — filters by tenant_id.
func GetPlaybookActionsByPlaybookID(playbookID string, tenantID int) ([]models.PlaybookAction, error) {
	rows, err := database.DB.Query(`
		SELECT
			id, playbook_id, step_order, action_type, payload,
			condition_expr, max_retries, retry_delay_secs, run_parallel, timeout_seconds,
			created_at,
			COALESCE(step_name,''), COALESCE(goto_on_success,''),
			COALESCE(goto_on_failure,''), COALESCE(stop_on_failure,FALSE),
			COALESCE(loop_over,'')
		FROM playbook_actions
		WHERE playbook_id = $1 AND tenant_id = $2
		ORDER BY step_order, id
	`, playbookID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	actions := []models.PlaybookAction{}
	for rows.Next() {
		var a models.PlaybookAction
		if err := rows.Scan(
			&a.ID, &a.PlaybookID, &a.StepOrder, &a.ActionType, &a.Payload,
			&a.ConditionExpr, &a.MaxRetries, &a.RetryDelaySecs, &a.RunParallel, &a.TimeoutSeconds,
			&a.CreatedAt,
			&a.StepName, &a.GotoOnSuccess, &a.GotoOnFailure, &a.StopOnFailure, &a.LoopOver,
		); err != nil {
			continue
		}
		actions = append(actions, a)
	}
	return actions, nil
}

func CreatePlaybookAction(action models.PlaybookAction, tenantID int) error {
	_, err := database.DB.Exec(`
		INSERT INTO playbook_actions
		(playbook_id, step_order, action_type, payload,
		 condition_expr, max_retries, retry_delay_secs, run_parallel, timeout_seconds,
		 tenant_id,
		 step_name, goto_on_success, goto_on_failure, stop_on_failure, loop_over)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
	`,
		action.PlaybookID, action.StepOrder, action.ActionType, action.Payload,
		action.ConditionExpr, action.MaxRetries, action.RetryDelaySecs,
		action.RunParallel, action.TimeoutSeconds,
		tenantID,
		action.StepName, action.GotoOnSuccess, action.GotoOnFailure,
		action.StopOnFailure, action.LoopOver,
	)
	return err
}

func DeletePlaybookAction(id string, tenantID int) error {
	tag, err := database.DB.Exec(
		`DELETE FROM playbook_actions WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrPlaybookActionNotFound
	}
	return nil
}
