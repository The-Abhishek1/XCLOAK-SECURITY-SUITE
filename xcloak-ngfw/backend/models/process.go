package models

import "time"

type Process struct {
	ID          int       `json:"id"`
	AgentID     int       `json:"agent_id"`
	PID         int       `json:"pid"`
	ProcessName string    `json:"process_name"`
	CollectedAt time.Time `json:"collected_at"`
}
