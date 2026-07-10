package repositories

import (
	"xcloak-platform/database"
	"xcloak-platform/models"
)

func SaveUsers(
	users []models.Users,
) error {

	if len(users) == 0 {
		return nil
	}

	tx, err := database.DB.Begin()

	if err != nil {
		return err
	}

	defer tx.Rollback()

	agentID := users[0].AgentID

	_, err = tx.Exec(`
		DELETE FROM endpoint_users
		WHERE agent_id = $1
	`, agentID)

	if err != nil {
		return err
	}

	for _, user := range users {

		_, err := tx.Exec(`
			INSERT INTO endpoint_users
			(agent_id, username, uid, shell)
			VALUES ($1,$2,$3,$4)
		`,
			user.AgentID,
			user.Username,
			user.UID,
			user.Shell,
		)

		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
