package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func GetAgentSummary(
	agentID string,
) (*models.AgentSummary, error) {

	return repositories.GetAgentSummary(
		agentID,
	)
}
