package models

import "time"

type ThreatFeed struct {
	ID int `json:"id"`

	Name string `json:"name"`

	Source string `json:"source"`

	Enabled bool `json:"enabled"`

	LastSync *time.Time `json:"last_sync"`

	CreatedAt time.Time `json:"created_at"`
}
