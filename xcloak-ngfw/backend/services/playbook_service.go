package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func CreatePlaybook(
	playbook models.Playbook,
) error {

	return repositories.CreatePlaybook(
		playbook,
	)
}

func GetPlaybooks() (
	[]models.Playbook,
	error,
) {

	return repositories.GetPlaybooks()
}
