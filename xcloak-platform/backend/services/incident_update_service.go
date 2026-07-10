package services

import (
	"fmt"

	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// UpdateIncidentStatus changes the status of an incident, scoped to
// tenantID — enforced here too (not just the API-layer pre-check in
// api/incident_update.go) so this function is safe to call from anywhere,
// not just call sites that remember to check ownership first.
func UpdateIncidentStatus(id int, status string, tenantID int) error {
	tag, err := database.DB.Exec(`
		UPDATE incidents SET status = $1 WHERE id = $2 AND tenant_id = $3
	`, status, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return fmt.Errorf("incident not found")
	}
	return nil
}

// AddIncidentEvent appends a timestamped event/note to an incident's
// timeline, scoped to tenantID for the same reason as UpdateIncidentStatus.
func AddIncidentEvent(incidentID int, eventType, details, _ string, tenantID int) error {
	if _, err := repositories.GetIncidentByID(fmt.Sprintf("%d", incidentID), tenantID); err != nil {
		return fmt.Errorf("incident not found")
	}
	return repositories.CreateIncidentEvent(models.IncidentEvent{
		IncidentID: incidentID,
		EventType:  eventType,
		Details:    details,
	})
}
