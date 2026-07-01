package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// CreatePlaybookExecutionRecord inserts a new execution row and returns its ID.
// tenant_id is resolved from the owning agent.
func CreatePlaybookExecutionRecord(e models.PlaybookExecution) (int, error) {
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO playbook_executions
		(playbook_id, agent_id, alert_rule, action_type, status, overall_status,
		 steps_total, steps_ok, steps_failed, steps_skipped, duration_ms, tenant_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,
		        (SELECT tenant_id FROM agents WHERE id = $2))
		RETURNING id
	`,
		e.PlaybookID, e.AgentID, e.AlertRule, e.ActionType, e.Status, e.OverallStatus,
		e.StepsTotal, e.StepsOK, e.StepsFailed, e.StepsSkipped, e.DurationMs,
	).Scan(&id)
	return id, err
}

// UpdatePlaybookExecutionSummary writes the final counts and status after all steps run.
func UpdatePlaybookExecutionSummary(id int, overallStatus string, total, ok, failed, skipped, durationMs int) error {
	_, err := database.DB.Exec(`
		UPDATE playbook_executions
		SET overall_status = $1, status = $1,
		    steps_total = $2, steps_ok = $3, steps_failed = $4,
		    steps_skipped = $5, duration_ms = $6
		WHERE id = $7
	`, overallStatus, total, ok, failed, skipped, durationMs, id)
	return err
}

// GetPlaybookExecutions returns all execution records for the tenant, newest first.
func GetPlaybookExecutions(tenantID int) ([]models.PlaybookExecution, error) {
	rows, err := database.DB.Query(`
		SELECT
			id, playbook_id, agent_id, alert_rule, action_type, status,
			COALESCE(error_detail,''), COALESCE(task_id,0), tenant_id,
			overall_status, steps_total, steps_ok, steps_failed, steps_skipped, duration_ms,
			created_at
		FROM playbook_executions
		WHERE tenant_id = $1
		ORDER BY id DESC
		LIMIT 200
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var execs []models.PlaybookExecution
	for rows.Next() {
		var e models.PlaybookExecution
		if err := rows.Scan(
			&e.ID, &e.PlaybookID, &e.AgentID, &e.AlertRule, &e.ActionType, &e.Status,
			&e.ErrorDetail, &e.TaskID, &e.TenantID,
			&e.OverallStatus, &e.StepsTotal, &e.StepsOK, &e.StepsFailed, &e.StepsSkipped, &e.DurationMs,
			&e.CreatedAt,
		); err == nil {
			execs = append(execs, e)
		}
	}
	return execs, nil
}

// CreatePlaybookStepResult records the outcome of a single step within an execution.
func CreatePlaybookStepResult(r models.PlaybookStepResult) error {
	_, err := database.DB.Exec(`
		INSERT INTO playbook_step_results
		(execution_id, step_order, action_type, condition_expr, status,
		 output, error_detail, retries_used, started_at, finished_at,
		 step_name, loop_item, goto_taken)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
	`,
		r.ExecutionID, r.StepOrder, r.ActionType, r.ConditionExpr, r.Status,
		r.Output, r.ErrorDetail, r.RetriesUsed, r.StartedAt, r.FinishedAt,
		r.StepName, r.LoopItem, r.GotoTaken,
	)
	return err
}

// GetPlaybookStepResults returns step results for one execution, verified by tenant.
func GetPlaybookStepResults(executionID, tenantID int) ([]models.PlaybookStepResult, error) {
	rows, err := database.DB.Query(`
		SELECT
			psr.id, psr.execution_id, psr.step_order, psr.action_type,
			psr.condition_expr, psr.status, psr.output, psr.error_detail,
			psr.retries_used, psr.started_at, psr.finished_at
		FROM playbook_step_results psr
		JOIN playbook_executions pe ON pe.id = psr.execution_id
		WHERE psr.execution_id = $1 AND pe.tenant_id = $2
		ORDER BY psr.step_order, psr.id
	`, executionID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []models.PlaybookStepResult
	for rows.Next() {
		var r models.PlaybookStepResult
		if err := rows.Scan(
			&r.ID, &r.ExecutionID, &r.StepOrder, &r.ActionType,
			&r.ConditionExpr, &r.Status, &r.Output, &r.ErrorDetail,
			&r.RetriesUsed, &r.StartedAt, &r.FinishedAt,
		); err == nil {
			results = append(results, r)
		}
	}
	return results, nil
}
