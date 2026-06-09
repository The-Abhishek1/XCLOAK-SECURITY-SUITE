package models

import "time"

type Package struct {
	ID          int       `json:"id"`
	AgentID     int       `json:"agent_id"`
	PackageName string    `json:"package_name"`
	Version     string    `json:"version"`
	CollectedAt time.Time `json:"collected_at"`
}
