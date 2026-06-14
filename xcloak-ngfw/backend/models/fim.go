package models

import "time"

type FIMBaseline struct {
	ID        int       `json:"id"`
	AgentID   int       `json:"agent_id"`
	FilePath  string    `json:"file_path"`
	SHA256    string    `json:"sha256_hash"`
	FileSize  int64     `json:"file_size"`
	CreatedAt time.Time `json:"created_at"`
}

type FIMAlert struct {
	ID         int       `json:"id"`
	AgentID    int       `json:"agent_id"`
	FilePath   string    `json:"file_path"`
	ChangeType string    `json:"change_type"` // modified, deleted, created
	OldHash    string    `json:"old_hash"`
	NewHash    string    `json:"new_hash"`
	CreatedAt  time.Time `json:"created_at"`
}

// FIMScanPayload is sent from the agent after scanning watched paths.
type FIMScanPayload struct {
	AgentID int                    `json:"agent_id"`
	Files   []FIMFileEntry         `json:"files"`
}

type FIMFileEntry struct {
	FilePath string `json:"file_path"`
	SHA256   string `json:"sha256_hash"`
	FileSize int64  `json:"file_size"`
}
