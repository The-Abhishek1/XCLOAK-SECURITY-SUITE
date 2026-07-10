package services

import (
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

func SaveProcesses(
	processes []models.Process,
) error {

	return repositories.SaveProcesses(
		processes,
	)
}
