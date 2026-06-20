package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func GetDashboardOverview(tenantID int) (*models.DashboardOverview, error) {

	return repositories.GetDashboardOverview(tenantID)
}
