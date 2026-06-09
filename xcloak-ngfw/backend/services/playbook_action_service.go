package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func CreatePlaybookAction(
	action models.PlaybookAction,
) error {

	return repositories.CreatePlaybookAction(
		action,
	)
}

func GetPlaybookActions(
	playbookID string,
) ([]models.PlaybookAction, error) {

	return repositories.GetPlaybookActionsByPlaybookID(
		playbookID,
	)
}

func DeletePlaybookAction(
	id string,
) error {

	return repositories.DeletePlaybookAction(
		id,
	)
}
