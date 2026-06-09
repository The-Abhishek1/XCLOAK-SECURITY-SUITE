package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func CreateThreatFeed(
	feed models.ThreatFeed,
) error {

	_, err := database.DB.Exec(`
		INSERT INTO threat_feeds
		(
			name,
			source,
			enabled
		)
		VALUES ($1,$2,$3)
	`,
		feed.Name,
		feed.Source,
		feed.Enabled,
	)

	return err
}

func GetThreatFeeds() (
	[]models.ThreatFeed,
	error,
) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			name,
			source,
			enabled,
			last_sync,
			created_at
		FROM threat_feeds
		ORDER BY id DESC
	`)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var feeds []models.ThreatFeed

	for rows.Next() {

		var feed models.ThreatFeed

		err := rows.Scan(
			&feed.ID,
			&feed.Name,
			&feed.Source,
			&feed.Enabled,
			&feed.LastSync,
			&feed.CreatedAt,
		)

		if err != nil {
			continue
		}

		feeds = append(
			feeds,
			feed,
		)
	}

	return feeds, nil
}
