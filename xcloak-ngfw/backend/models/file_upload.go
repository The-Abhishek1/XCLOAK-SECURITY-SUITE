package models

type FileUpload struct {
	AgentID      int    `json:"agent_id"`
	OriginalPath string `json:"original_path"`
	FileName     string `json:"file_name"`
	Content      string `json:"content"`
}
