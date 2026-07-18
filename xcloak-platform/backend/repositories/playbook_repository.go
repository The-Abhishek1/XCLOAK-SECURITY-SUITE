package repositories

import (
	"xcloak-platform/database"
	"xcloak-platform/models"
)

func CreatePlaybook(
	playbook models.Playbook,
	tenantID int,
) error {

	_, err := database.DB.Exec(`
		INSERT INTO playbooks
		(
			name,
			trigger_type,
			action_type,
			enabled,
			tenant_id
		)
		VALUES ($1,$2,$3,$4,$5)
	`,
		playbook.Name,
		playbook.TriggerType,
		playbook.ActionType,
		playbook.Enabled,
		tenantID,
	)

	return err
}

// GetPlaybooks returns playbooks belonging to tenantID only. Use this from
// user-facing API paths that have a real tenant context from the request.
func GetPlaybooks(tenantID int) (
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
			tenant_id,
			created_at
		FROM playbooks
		WHERE tenant_id = $1
		ORDER BY id DESC
	`, tenantID)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	playbooks := []models.Playbook{}

	for rows.Next() {

		var p models.Playbook

		err := rows.Scan(
			&p.ID,
			&p.Name,
			&p.TriggerType,
			&p.ActionType,
			&p.Enabled,
			&p.TenantID,
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

// GetPlaybookByID fetches a single playbook, scoped to tenantID — a request
// for another tenant's playbook gets the same error as a nonexistent one.
func GetPlaybookByID(id int, tenantID int) (*models.Playbook, error) {

	var p models.Playbook

	err := database.DB.QueryRow(`
		SELECT id, name, trigger_type, action_type, enabled, tenant_id, created_at
		FROM playbooks
		WHERE id = $1 AND tenant_id = $2
	`, id, tenantID).Scan(
		&p.ID, &p.Name, &p.TriggerType, &p.ActionType, &p.Enabled, &p.TenantID, &p.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &p, nil
}

// GetEnabledPlaybooksForAgent returns enabled playbooks for the tenant that
// owns agentID — used by the SOAR engine, which only has an agent_id to
// work from (no per-request tenant context).
func GetEnabledPlaybooksForAgent(agentID int) (
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
			tenant_id,
			created_at
		FROM playbooks
		WHERE enabled=true
		  AND tenant_id = (SELECT tenant_id FROM agents WHERE id = $1)
	`, agentID)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	playbooks := []models.Playbook{}

	for rows.Next() {

		var p models.Playbook

		if err := rows.Scan(
			&p.ID,
			&p.Name,
			&p.TriggerType,
			&p.ActionType,
			&p.Enabled,
			&p.TenantID,
			&p.CreatedAt,
		); err != nil {
			return nil, err
		}

		playbooks = append(
			playbooks,
			p,
		)
	}

	return playbooks, rows.Err()
}
