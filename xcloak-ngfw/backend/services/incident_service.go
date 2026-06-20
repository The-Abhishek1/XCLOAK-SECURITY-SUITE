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

	if err != nil {
		return 0, err
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
