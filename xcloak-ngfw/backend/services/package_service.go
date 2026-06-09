package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func SavePackages(
	packages []models.Package,
) error {

	return repositories.SavePackages(
		packages,
	)
}
