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

		if IsKafkaEnabled() {
			PublishConnectionMatchJob(conn)
		} else {
			CheckConnectionIOC(conn)
		}
	}

	return nil
}
