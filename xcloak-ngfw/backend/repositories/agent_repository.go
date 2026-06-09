package repositories

import (
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func RegisterAgent(agent models.Agent) (int, error) {

	query := `
	INSERT INTO agents
	(hostname, os, ip_address, status, last_seen)
	VALUES ($1,$2,$3,$4,$5)
	RETURNING id
	`

	var agentID int

	err := database.DB.QueryRow(
		query,
		agent.Hostname,
		agent.OS,
		agent.IPAddress,
		"online",
		time.Now(),
	).Scan(&agentID)

	if err != nil {
		return 0, err
	}

	return agentID, nil
}

func GetAgents() ([]models.Agent, error) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			hostname,
			os,
			ip_address,
			status,
			last_seen,
			created_at
		FROM agents
		ORDER BY id
	`)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var agents []models.Agent

	for rows.Next() {

		var agent models.Agent

		err := rows.Scan(
			&agent.ID,
			&agent.Hostname,
			&agent.OS,
			&agent.IPAddress,
			&agent.Status,
			&agent.LastSeen,
			&agent.CreatedAt,
		)

		if err != nil {
			continue
		}

		agents = append(agents, agent)
	}

	return agents, nil
}

func GetAgentByID(id string) (*models.Agent, error) {

	var agent models.Agent

	query := `
	SELECT
		id,
		hostname,
		os,
		ip_address,
		status,
		last_seen,
		created_at
	FROM agents
	WHERE id = $1
	`

	err := database.DB.QueryRow(
		query,
		id,
	).Scan(
		&agent.ID,
		&agent.Hostname,
		&agent.OS,
		&agent.IPAddress,
		&agent.Status,
		&agent.LastSeen,
		&agent.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &agent, nil
}

func UpdateAgentHeartbeat(
	agentID int,
) error {

	query := `
	UPDATE agents
	SET
		last_seen = NOW(),
		status = 'online'
	WHERE id = $1
	`

	_, err := database.DB.Exec(
		query,
		agentID,
	)

	return err
}
