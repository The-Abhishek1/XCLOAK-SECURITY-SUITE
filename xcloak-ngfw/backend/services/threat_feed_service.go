package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func CreateThreatFeed(
	feed models.ThreatFeed,
) error {

	return repositories.CreateThreatFeed(
		feed,
	)
}

func GetThreatFeeds() (
	[]models.ThreatFeed,
	error,
) {

	return repositories.GetThreatFeeds()
}
