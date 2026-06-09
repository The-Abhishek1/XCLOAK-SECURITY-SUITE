package models

// FileHash represents a hashed file collected from an endpoint.
// Sent in bulk to /api/filehashes after a collect_file_hashes task.
type FileHash struct {
	AgentID    int    `json:"agent_id"`
	FilePath   string `json:"file_path"`
	FileName   string `json:"file_name"`
	MD5Hash    string `json:"md5_hash"`
	SHA256Hash string `json:"sha256_hash"`
	FileSize   int64  `json:"file_size"`
}
