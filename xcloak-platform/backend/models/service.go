package models

import "time"

type Service struct {
	ID           int       `json:"id"`
	AgentID      int       `json:"agent_id"`
	ServiceName  string    `json:"service_name"`
	ServiceState string    `json:"service_state"`
	CollectedAt  time.Time `json:"collected_at"`
}
