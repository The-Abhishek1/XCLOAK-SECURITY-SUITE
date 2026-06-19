package models

import "time"

type Log struct {
	ID           int       `json:"id"`
	AgentID      int       `json:"agent_id"`
	LogSource    string    `json:"log_source"`
	LogMessage   string    `json:"log_message"`
	ParsedFields string    `json:"parsed_fields,omitempty"` // JSONB stored as string
	CollectedAt  time.Time `json:"collected_at"`
}
