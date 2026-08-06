package models

import "time"

type AgentSummary struct {
	AgentID  int        `json:"agent_id"`
	Hostname string     `json:"hostname"`
	Status   string     `json:"status"`
	LastSeen *time.Time `json:"last_seen,omitempty"`

	Processes   int `json:"processes"`
	Connections int `json:"connections"`
	Services    int `json:"services"`
	Packages    int `json:"packages"`
	Users       int `json:"users"`
}
