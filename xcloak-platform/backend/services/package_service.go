package services

import (
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

func SavePackages(
	packages []models.Package,
) error {

	return repositories.SavePackages(
		packages,
	)
}
