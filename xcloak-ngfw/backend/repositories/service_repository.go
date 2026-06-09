package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func SaveServices(
	services []models.Service,
) error {

	tx, err := database.DB.Begin()

	if err != nil {
		return err
	}

	defer tx.Rollback()

	if len(services) == 0 {
		return nil
	}

	agentID := services[0].AgentID

	_, err = tx.Exec(`
		DELETE FROM endpoint_services
		WHERE agent_id = $1
	`, agentID)

	if err != nil {
		return err
	}

	for _, service := range services {

		_, err := tx.Exec(`
			INSERT INTO endpoint_services
			(agent_id, service_name, service_state)
			VALUES ($1,$2,$3)
		`,
			service.AgentID,
			service.ServiceName,
			service.ServiceState,
		)

		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
