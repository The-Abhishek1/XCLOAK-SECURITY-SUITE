package models

import "time"

// FileHash is a hashed file record stored in endpoint_file_hashes.
type FileHash struct {
	ID          int       `json:"id"`
	AgentID     int       `json:"agent_id"`
	FilePath    string    `json:"file_path"`
	FileName    string    `json:"file_name"`
	MD5Hash     string    `json:"md5_hash"`
	SHA256Hash  string    `json:"sha256_hash"`
	FileSize    int64     `json:"file_size"`
	CollectedAt time.Time `json:"collected_at"`
}
