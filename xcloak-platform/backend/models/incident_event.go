package models

import "time"

type IncidentEvent struct {
	ID         int       `json:"id"`
	IncidentID int       `json:"incident_id"`
	EventType  string    `json:"event_type"`
	Details    string    `json:"details"`
	CreatedAt  time.Time `json:"created_at"`
}
