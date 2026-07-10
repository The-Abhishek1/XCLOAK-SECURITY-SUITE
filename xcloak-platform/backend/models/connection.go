package models

import "time"

type Connection struct {
	ID            int       `json:"id"`
	AgentID       int       `json:"agent_id"`
	Protocol      string    `json:"protocol"`
	LocalAddress  string    `json:"local_address"`
	RemoteAddress string    `json:"remote_address"`
	State         string    `json:"state"`
	CollectedAt   time.Time `json:"collected_at"`
}
