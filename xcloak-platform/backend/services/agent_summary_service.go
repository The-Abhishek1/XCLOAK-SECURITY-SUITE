package services

import (
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

func GetAgentSummary(
	agentID string,
) (*models.AgentSummary, error) {

	return repositories.GetAgentSummary(
		agentID,
	)
}
