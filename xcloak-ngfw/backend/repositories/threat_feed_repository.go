package repositories

import (
	"fmt"

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

func UpdateThreatFeed(id string, feed models.ThreatFeed, tenantID int) error {
	config := feed.Config
	if len(config) == 0 {
		config = []byte("{}")
	}
	_, err := database.DB.Exec(`
		UPDATE threat_feeds
		SET name=$1, source=$2, enabled=$3, feed_type=$4, config=$5
		WHERE id=$6 AND tenant_id=$7
	`, feed.Name, feed.Source, feed.Enabled, feed.FeedType, config, id, tenantID)
	return err
}

func DeleteThreatFeed(id string, tenantID int) error {
	res, err := database.DB.Exec(`DELETE FROM threat_feeds WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("not found")
	}
	return nil
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
