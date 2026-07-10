package services

import (
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

func SaveServices(
	services []models.Service,
) error {

	return repositories.SaveServices(
		services,
	)
}
