package services

import (
	"xcloak-ngfw/database"
)

func MarkOfflineAgents() {

	query := `
	UPDATE agents
	SET status = 'offline'
	WHERE last_seen < NOW() - INTERVAL '2 minutes'
	`

	database.DB.Exec(query)
}
