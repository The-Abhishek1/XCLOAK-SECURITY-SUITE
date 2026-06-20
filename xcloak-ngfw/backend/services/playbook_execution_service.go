package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func LogPlaybookExecution(
	execution models.PlaybookExecution,
) error {

	return repositories.CreatePlaybookExecution(
		execution,
	)
}

func GetPlaybookExecutions(tenantID int) (
	[]models.PlaybookExecution,
	error,
) {

	return repositories.GetPlaybookExecutions(tenantID)
}
