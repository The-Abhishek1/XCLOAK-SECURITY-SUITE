package services

import (
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

func SaveUsers(
	users []models.Users,
) error {

	return repositories.SaveUsers(
		users,
	)
}
