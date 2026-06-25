package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func CreateIncident(
	incident models.Incident,
) (int, error) {

	id, err := repositories.CreateIncident(
		incident,
	)

	// On a dedup hit, id is the existing incident's ID — callers (see
	// correlation_service.go) already branch on err != nil to look up and
	// log against the existing incident, so id must survive past this
	// check rather than being discarded to 0 alongside every other error.
	if err != nil {
		return id, err
	}

	err = CalculateRiskScore(
		incident.AgentID,
	)

	if err != nil {
		return id, err
	}

	return id, nil
}

func GetIncidents(tenantID int) ([]models.Incident, error) {

	return repositories.GetIncidents(tenantID)
}
