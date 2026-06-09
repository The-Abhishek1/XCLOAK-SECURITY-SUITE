package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func CreateIncidentEvent(
	event models.IncidentEvent,
) error {

	return repositories.CreateIncidentEvent(
		event,
	)
}

func GetIncidentEvents(
	incidentID string,
) ([]models.IncidentEvent, error) {

	return repositories.GetIncidentEvents(
		incidentID,
	)
}
