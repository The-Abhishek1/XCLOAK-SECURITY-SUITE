package services

import (
	"fmt"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func GetPlaybookExecutions(tenantID int) ([]models.PlaybookExecution, error) {
	return repositories.GetPlaybookExecutions(tenantID)
}

func GetPlaybookStepResults(executionID string, tenantID int) ([]models.PlaybookStepResult, error) {
	var id int
	fmt.Sscan(executionID, &id)
	return repositories.GetPlaybookStepResults(id, tenantID)
}
