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

func GetPlaybookExecutions() (
	[]models.PlaybookExecution,
	error,
) {

	return repositories.GetPlaybookExecutions()
}
