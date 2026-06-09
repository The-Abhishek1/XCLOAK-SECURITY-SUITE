package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func CreateIncident(
	incident models.Incident,
) (int, error) {

	if IncidentExists(
		incident.Fingerprint,
	) {
		return 0, nil
	}

	var incidentID int

	err := database.DB.QueryRow(`
		INSERT INTO incidents
		(
			agent_id,
			title,
			severity,
			description,
			fingerprint
		)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id
	`,
		incident.AgentID,
		incident.Title,
		incident.Severity,
		incident.Description,
		incident.Fingerprint,
	).Scan(&incidentID)

	if err != nil {
		return 0, err
	}

	return incidentID, nil
}

func GetIncidents() ([]models.Incident, error) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			agent_id,
			title,
			severity,
			status,
			description,
			created_at
		FROM incidents
		ORDER BY created_at DESC
	`)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var incidents []models.Incident

	for rows.Next() {

		var incident models.Incident

		err := rows.Scan(
			&incident.ID,
			&incident.AgentID,
			&incident.Title,
			&incident.Severity,
			&incident.Status,
			&incident.Description,
			&incident.CreatedAt,
		)

		if err != nil {
			continue
		}

		incidents = append(
			incidents,
			incident,
		)
	}

	return incidents, nil
}

func IncidentExists(
	fingerprint string,
) bool {

	var count int

	err := database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM incidents
		WHERE
			fingerprint = $1
			AND created_at >
			NOW() - INTERVAL '1 hour'
	`,
		fingerprint,
	).Scan(&count)

	if err != nil {
		return false
	}

	return count > 0
}
