package models

import "time"

type IOC struct {
	ID int `json:"id"`

	Indicator string `json:"indicator"`

	Type string `json:"type"`

	Severity string `json:"severity"`

	Description string `json:"description"`

	Enabled bool `json:"enabled"`

	CreatedAt time.Time `json:"created_at"`
}
