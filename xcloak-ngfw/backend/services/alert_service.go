package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func CreateAlert(
	alert models.Alert,
) error {

	err := repositories.CreateAlert(
		alert,
	)

	if err != nil {
		return err
	}

	ExecutePlaybooks(alert)

	CalculateRiskScore(
		alert.AgentID,
	)

	return nil
}

func GetAlerts() ([]models.Alert, error) {

	return repositories.GetAlerts()
}
