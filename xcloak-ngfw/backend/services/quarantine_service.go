package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func SaveQuarantinedFile(
	file models.QuarantinedFile,
) error {

	return repositories.SaveQuarantinedFile(
		file,
	)
}

func GetQuarantinedFiles(tenantID int) ([]models.QuarantinedFile, error) {

	return repositories.GetQuarantinedFiles(tenantID)
}
