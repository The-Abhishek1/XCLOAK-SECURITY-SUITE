package models

import "time"

type Incident struct {
	ID          int       `json:"id"`
	AgentID     int       `json:"agent_id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	Fingerprint string    `json:"fingerprint"`
}
