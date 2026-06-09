package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func SaveProcesses(
	processes []models.Process,
) error {

	if len(processes) == 0 {
		return nil
	}

	tx, err := database.DB.Begin()

	if err != nil {
		return err
	}

	defer tx.Rollback()

	agentID := processes[0].AgentID

	_, err = tx.Exec(`
		DELETE FROM endpoint_processes
		WHERE agent_id = $1
	`, agentID)

	if err != nil {
		return err
	}

	for _, p := range processes {

		_, err := tx.Exec(`
			INSERT INTO endpoint_processes
			(agent_id, pid, process_name)
			VALUES ($1,$2,$3)
		`,
			p.AgentID,
			p.PID,
			p.ProcessName,
		)

		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
