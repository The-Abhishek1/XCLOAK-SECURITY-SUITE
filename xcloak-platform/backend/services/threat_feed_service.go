package services

import (
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

func CreateThreatFeed(
	feed models.ThreatFeed,
	tenantID int,
) error {

	return repositories.CreateThreatFeed(
		feed,
		tenantID,
	)
}

func GetThreatFeeds(tenantID int) (
	[]models.ThreatFeed,
	error,
) {

	return repositories.GetThreatFeeds(tenantID)
}
