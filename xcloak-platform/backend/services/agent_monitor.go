package services

import (
	"xcloak-platform/database"
)

func MarkOfflineAgents() {

	query := `
	UPDATE agents
	SET status = 'offline'
	WHERE last_seen < NOW() - INTERVAL '8 minutes'
	`

	database.DB.Exec(query)
}
