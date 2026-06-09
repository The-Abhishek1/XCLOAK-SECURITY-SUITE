package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func SaveConnections(
	connections []models.Connection,
) error {

	tx, err := database.DB.Begin()

	if err != nil {
		return err
	}

	defer tx.Rollback()

	if len(connections) == 0 {
		return nil
	}

	agentID := connections[0].AgentID

	_, err = tx.Exec(`
		DELETE FROM endpoint_connections
		WHERE agent_id = $1
	`, agentID)

	if err != nil {
		return err
	}

	for _, c := range connections {

		_, err := tx.Exec(`
			INSERT INTO endpoint_connections
			(agent_id, protocol, local_address,
			 remote_address, state)
			VALUES ($1,$2,$3,$4,$5)
		`,
			c.AgentID,
			c.Protocol,
			c.LocalAddress,
			c.RemoteAddress,
			c.State,
		)

		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
