package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func GetDashboardOverview() (*models.DashboardOverview, error) {

	return repositories.GetDashboardOverview()
}
