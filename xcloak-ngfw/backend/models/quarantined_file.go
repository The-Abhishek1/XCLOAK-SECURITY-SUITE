package models

import "time"

type QuarantinedFile struct {
	ID             int       `json:"id"`
	AgentID        int       `json:"agent_id"`
	OriginalPath   string    `json:"original_path"`
	QuarantinePath string    `json:"quarantine_path"`
	FileName       string    `json:"file_name"`
	Reason         string    `json:"reason"`
	QuarantinedAt  time.Time `json:"quarantined_at"`
}
