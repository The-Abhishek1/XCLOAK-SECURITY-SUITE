package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func SaveLogs(
	logs []models.Log,
) error {

	err := repositories.SaveLogs(
		logs,
	)

	if err != nil {
		return err
	}

	for _, log := range logs {

		EvaluateRules(
			log,
		)
	}

	return nil
}
