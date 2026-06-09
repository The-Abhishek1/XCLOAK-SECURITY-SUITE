package models

import "time"

type Users struct {
	ID          int       `json:"id"`
	AgentID     int       `json:"agent_id"`
	Username    string    `json:"username"`
	UID         int       `json:"uid"`
	Shell       string    `json:"shell"`
	CollectedAt time.Time `json:"collected_at"`
}
