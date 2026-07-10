package services

import (
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

func CreatePlaybook(
	playbook models.Playbook,
	tenantID int,
) error {

	return repositories.CreatePlaybook(
		playbook,
		tenantID,
	)
}

func GetPlaybooks(tenantID int) (
	[]models.Playbook,
	error,
) {

	return repositories.GetPlaybooks(tenantID)
}
