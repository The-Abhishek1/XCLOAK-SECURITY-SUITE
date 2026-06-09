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

func GetQuarantinedFiles() ([]models.QuarantinedFile, error) {

	return repositories.GetQuarantinedFiles()
}
