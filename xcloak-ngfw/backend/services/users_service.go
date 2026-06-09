package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func SaveUsers(
	users []models.Users,
) error {

	return repositories.SaveUsers(
		users,
	)
}
