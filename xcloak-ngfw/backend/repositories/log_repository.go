package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func SaveLogs(
	logs []models.Log,
) error {

	if len(logs) == 0 {
		return nil
	}

	tx, err := database.DB.Begin()

	if err != nil {
		return err
	}

	defer tx.Rollback()

	for _, log := range logs {

		_, err := tx.Exec(`
			INSERT INTO endpoint_logs
			(agent_id, log_source, log_message)
			VALUES ($1,$2,$3)
		`,
			log.AgentID,
			log.LogSource,
			log.LogMessage,
		)

		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
