package models

import (
	"encoding/json"
	"time"
)

type TimelineEvent struct {
	ID             int             `json:"id,omitempty"`
	AgentID        int             `json:"agent_id,omitempty"`
	EventType      string          `json:"event_type"`
	Message        string          `json:"message"`
	Severity       string          `json:"severity,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	Hostname       string          `json:"hostname,omitempty"`
	Username       string          `json:"username,omitempty"`
	ProcessName    string          `json:"process_name,omitempty"`
	MitreTechnique string          `json:"mitre_technique,omitempty"`
	MitreName      string          `json:"mitre_name,omitempty"`
	Source         string          `json:"source,omitempty"`
	Details        json.RawMessage `json:"details,omitempty"`
}
