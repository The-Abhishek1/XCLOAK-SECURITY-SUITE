package models

type YaraMatch struct {
	AgentID int `json:"agent_id"`

	FilePath string `json:"file_path"`

	RuleName string `json:"rule_name"`

	Severity string `json:"severity"`

	Description string `json:"description"`
}
