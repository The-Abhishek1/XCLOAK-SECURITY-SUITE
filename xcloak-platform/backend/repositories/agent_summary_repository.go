package repositories

import (
	"xcloak-platform/database"
	"xcloak-platform/models"
)

func GetAgentSummary(
	agentID string,
) (*models.AgentSummary, error) {

	var summary models.AgentSummary

	err := database.DB.QueryRow(`
		SELECT
			id,
			hostname,
			status
		FROM agents
		WHERE id = $1
	`,
		agentID,
	).Scan(
		&summary.AgentID,
		&summary.Hostname,
		&summary.Status,
	)

	if err != nil {
		return nil, err
	}

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM endpoint_processes
		WHERE agent_id = $1
	`, agentID).Scan(
		&summary.Processes,
	)

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM endpoint_connections
		WHERE agent_id = $1
	`, agentID).Scan(
		&summary.Connections,
	)

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM endpoint_services
		WHERE agent_id = $1
	`, agentID).Scan(
		&summary.Services,
	)

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM endpoint_packages
		WHERE agent_id = $1
	`, agentID).Scan(
		&summary.Packages,
	)

	database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM endpoint_users
		WHERE agent_id = $1
	`, agentID).Scan(
		&summary.Users,
	)

	return &summary, nil
}
