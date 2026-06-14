package services

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// UpdateIncidentStatus changes the status of an incident.
func UpdateIncidentStatus(id int, status string) error {
	_, err := database.DB.Exec(`
		UPDATE incidents SET status = $1 WHERE id = $2
	`, status, id)
	return err
}

// AddIncidentEvent appends a timestamped event/note to an incident's timeline.
func AddIncidentEvent(incidentID int, eventType, details, _ string) error {
	return repositories.CreateIncidentEvent(models.IncidentEvent{
		IncidentID: incidentID,
		EventType:  eventType,
		Details:    details,
	})
}
