package models

import "time"

type CollectedFile struct {
	ID           int       `json:"id"`
	AgentID      int       `json:"agent_id"`
	OriginalPath string    `json:"original_path"`
	FileName     string    `json:"file_name"`
	StoredPath   string    `json:"stored_path"`
	CollectedAt  time.Time `json:"collected_at"`
}
