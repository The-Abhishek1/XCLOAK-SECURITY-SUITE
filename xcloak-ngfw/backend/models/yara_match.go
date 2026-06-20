package models

import "time"

type YaraMatch struct {
	ID int `json:"id"`

	AgentID int `json:"agent_id"`

	TenantID int `json:"tenant_id"`

	FilePath string `json:"file_path"`

	RuleName string `json:"rule_name"`

	Severity string `json:"severity"`

	Description string `json:"description"`

	CreatedAt time.Time `json:"created_at"`
}
