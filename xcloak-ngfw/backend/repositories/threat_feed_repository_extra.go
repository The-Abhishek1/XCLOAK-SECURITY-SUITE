// ADD THESE TWO FUNCTIONS to the END of:
// xcloak-ngfw/backend/repositories/threat_feed_repository.go
// (the file already has package repositories + imports database/models)

package repositories

import (
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// GetThreatFeedByID fetches a single feed, scoped to tenantID — a request
// for another tenant's feed gets the same error as a nonexistent one.
func GetThreatFeedByID(id string, tenantID int) (*models.ThreatFeed, error) {

	var feed models.ThreatFeed
	var configStr string

	err := database.DB.QueryRow(`
		SELECT id, name, source, enabled, feed_type, COALESCE(config::text, '{}'), last_sync, tenant_id, created_at
		FROM threat_feeds
		WHERE id = $1 AND tenant_id = $2
	`, id, tenantID).Scan(
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
		return nil, err
	}

	feed.Config = []byte(configStr)

	return &feed, nil
}

func UpdateThreatFeedLastSync(id int, t time.Time) error {

	_, err := database.DB.Exec(`
		UPDATE threat_feeds SET last_sync = $1 WHERE id = $2
	`, t, id)

	return err
}
