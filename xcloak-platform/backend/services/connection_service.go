package services

import (
	"xcloak-platform/models"
	"xcloak-platform/repositories"
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
