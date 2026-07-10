package services

import (
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

func GetDashboardOverview(tenantID int) (*models.DashboardOverview, error) {

	return repositories.GetDashboardOverview(tenantID)
}
