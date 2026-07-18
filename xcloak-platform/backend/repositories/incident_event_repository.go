package repositories

import (
	"xcloak-platform/database"
	"xcloak-platform/models"
)

func CreateIncidentEvent(
	event models.IncidentEvent,
) error {

	_, err := database.DB.Exec(`
		INSERT INTO incident_events
		(
			incident_id,
			event_type,
			details
		)
		VALUES ($1,$2,$3)
	`,
		event.IncidentID,
		event.EventType,
		event.Details,
	)

	return err
}

func GetIncidentEvents(
	incidentID string,
) ([]models.IncidentEvent, error) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			incident_id,
			event_type,
			details,
			created_at
		FROM incident_events
		WHERE incident_id = $1
		ORDER BY created_at
	`,
		incidentID,
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	events := []models.IncidentEvent{}

	for rows.Next() {

		var event models.IncidentEvent

		err := rows.Scan(
			&event.ID,
			&event.IncidentID,
			&event.EventType,
			&event.Details,
			&event.CreatedAt,
		)

		if err != nil {
			continue
		}

		events = append(events, event)
	}

	return events, nil
}
