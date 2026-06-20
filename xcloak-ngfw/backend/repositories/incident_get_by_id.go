package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// GetIncidentByID fetches a single incident by its ID, scoped to tenantID —
// a request for another tenant's incident gets the same "not found" as a
// nonexistent one, so existence isn't leaked across tenants (matches
// GetAgentByID's pattern).
func GetIncidentByID(id string, tenantID int) (*models.Incident, error) {

	var i models.Incident

	err := database.DB.QueryRow(`
		SELECT id, agent_id, title, severity, status, description, created_at, tenant_id
		FROM incidents WHERE id = $1 AND tenant_id = $2
	`, id, tenantID).Scan(&i.ID, &i.AgentID, &i.Title, &i.Severity, &i.Status, &i.Description, &i.CreatedAt, &i.TenantID)

	if err != nil {
		return nil, err
	}

	return &i, nil
}
