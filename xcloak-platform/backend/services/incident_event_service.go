package services

import (
	"xcloak-platform/models"
	"xcloak-platform/repositories"
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
