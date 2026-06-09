package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func SaveServices(
	services []models.Service,
) error {

	return repositories.SaveServices(
		services,
	)
}
