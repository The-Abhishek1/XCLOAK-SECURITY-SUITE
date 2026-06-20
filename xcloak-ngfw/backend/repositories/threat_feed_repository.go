package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func CreateThreatFeed(
	feed models.ThreatFeed,
	tenantID int,
) error {

	feedType := feed.FeedType
	if feedType == "" {
		feedType = "flatfile"
	}
	config := feed.Config
	if len(config) == 0 {
		config = []byte("{}")
	}

	_, err := database.DB.Exec(`
		INSERT INTO threat_feeds
		(
			name,
			source,
			enabled,
			feed_type,
			config,
			tenant_id
		)
		VALUES ($1,$2,$3,$4,$5,$6)
	`,
		feed.Name,
		feed.Source,
		feed.Enabled,
		feedType,
		config,
		tenantID,
	)

	return err
}

// GetThreatFeeds returns feeds belonging to tenantID only. Use this from
// user-facing API paths that have a real tenant context from the request.
func GetThreatFeeds(tenantID int) (
	[]models.ThreatFeed,
	error,
) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			name,
			source,
			enabled,
			feed_type,
			COALESCE(config::text, '{}'),
			last_sync,
			tenant_id,
			created_at
		FROM threat_feeds
		WHERE tenant_id = $1
		ORDER BY id DESC
	`, tenantID)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var feeds []models.ThreatFeed

	for rows.Next() {

		var feed models.ThreatFeed
		var configStr string

		err := rows.Scan(
			&feed.ID,
			&feed.Name,
			&feed.Source,
			&feed.Enabled,
			&feed.FeedType,
			&configStr,
			&feed.LastSync,
			&feed.TenantID,
			&feed.CreatedAt,
		)

		if err != nil {
			continue
		}

		feed.Config = []byte(configStr)

		feeds = append(
			feeds,
			feed,
		)
	}

	return feeds, nil
}
