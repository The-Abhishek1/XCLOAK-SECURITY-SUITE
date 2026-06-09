package models

type FileHash struct {
	AgentID    int    `json:"agent_id"`
	FilePath   string `json:"file_path"`
	MD5Hash    string `json:"md5_hash"`
	SHA256Hash string `json:"sha256_hash"`
}
