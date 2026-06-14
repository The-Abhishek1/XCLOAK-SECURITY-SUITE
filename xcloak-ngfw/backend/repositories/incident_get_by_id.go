package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// GetIncidentByID fetches a single incident by its ID.
func GetIncidentByID(id string) (*models.Incident, error) {

	var i models.Incident

	err := database.DB.QueryRow(`
		SELECT id, agent_id, title, severity, status, description, created_at
		FROM incidents WHERE id = $1
	`, id).Scan(&i.ID, &i.AgentID, &i.Title, &i.Severity, &i.Status, &i.Description, &i.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &i, nil
}
