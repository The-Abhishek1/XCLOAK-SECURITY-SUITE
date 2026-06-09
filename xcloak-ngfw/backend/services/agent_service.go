package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func RegisterAgent(
	agent models.Agent,
) (int, error) {

	agentID, err := repositories.RegisterAgent(agent)

	if err != nil {
		return 0, err
	}

	LogEvent(
		"REGISTER_AGENT",
		agent.Hostname,
		"system",
	)

	return agentID, nil
}

func GetAgents() ([]models.Agent, error) {

	return repositories.GetAgents()
}

func GetAgentByID(
	id string,
) (*models.Agent, error) {

	return repositories.GetAgentByID(id)
}

func Heartbeat(
	agentID int,
) error {

	return repositories.UpdateAgentHeartbeat(
		agentID,
	)
}
