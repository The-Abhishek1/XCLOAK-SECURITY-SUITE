package models

import "time"

type TimelineEvent struct {
	ID        int       `json:"id,omitempty"`
	AgentID   int       `json:"agent_id,omitempty"`
	EventType string    `json:"event_type"`
	Message   string    `json:"message"`
	Severity  string    `json:"severity,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
