package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func SaveProcesses(
	processes []models.Process,
) error {

	return repositories.SaveProcesses(
		processes,
	)
}
