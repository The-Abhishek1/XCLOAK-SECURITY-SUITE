package models

import (
	"encoding/json"
	"time"
)

type ThreatFeed struct {
	ID int `json:"id"`

	Name string `json:"name"`

	Source string `json:"source"`

	Enabled bool `json:"enabled"`

	// FeedType selects the ingestion protocol: "flatfile" (default — existing
	// one-indicator-per-line feeds), "otx", "misp", or "taxii".
	FeedType string `json:"feed_type"`

	// Config holds protocol-specific settings (api_key, collection_id,
	// username/password for TAXII basic auth, etc). See ThreatFeedConfig.
	Config json.RawMessage `json:"config"`

	LastSync *time.Time `json:"last_sync"`

	CreatedAt time.Time `json:"created_at"`
}

// ThreatFeedConfig is the parsed shape of ThreatFeed.Config. Every field is
// optional since each feed type only needs a subset.
type ThreatFeedConfig struct {
	APIKey       string `json:"api_key"`
	CollectionID string `json:"collection_id"` // TAXII
	Username     string `json:"username"`      // TAXII basic auth
	Password     string `json:"password"`      // TAXII basic auth
}
