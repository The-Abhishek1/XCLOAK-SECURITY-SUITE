package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func SaveConnections(
	connections []models.Connection,
) error {

	err := repositories.SaveConnections(
		connections,
	)

	if err != nil {
		return err
	}

	for _, conn := range connections {

		CheckConnectionIOC(conn)
	}

	return nil
}
