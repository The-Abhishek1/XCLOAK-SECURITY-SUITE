package models

import "time"

type FIMBaseline struct {
	ID        int        `json:"id"`
	AgentID   int        `json:"agent_id"`
	FilePath  string     `json:"file_path"`
	SHA256    string     `json:"sha256_hash"`
	FileSize  int64      `json:"file_size"`
	FileMode  string     `json:"file_mode,omitempty"`
	FileUID   int        `json:"file_uid,omitempty"`
	FileGID   int        `json:"file_gid,omitempty"`
	ModTime   *time.Time `json:"mod_time,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type FIMAlert struct {
	ID         int       `json:"id"`
	AgentID    int       `json:"agent_id"`
	FilePath   string    `json:"file_path"`
	ChangeType string    `json:"change_type"` // modified, permission_change, deleted, created
	OldHash    string    `json:"old_hash"`
	NewHash    string    `json:"new_hash"`
	OldMode    string    `json:"old_mode,omitempty"`
	NewMode    string    `json:"new_mode,omitempty"`
	OldUID     int       `json:"old_uid,omitempty"`
	NewUID     int       `json:"new_uid,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// FIMScanPayload is sent from the agent after scanning watched paths.
type FIMScanPayload struct {
	AgentID int            `json:"agent_id"`
	Files   []FIMFileEntry `json:"files"`
}

type FIMFileEntry struct {
	FilePath string     `json:"file_path"`
	SHA256   string     `json:"sha256_hash"`
	FileSize int64      `json:"file_size"`
	Mode     string     `json:"mode,omitempty"`
	UID      int        `json:"uid,omitempty"`
	GID      int        `json:"gid,omitempty"`
	ModTime  *time.Time `json:"mod_time,omitempty"`
}
