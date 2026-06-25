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

	// MatchedStrings is a JSON-encoded array of {identifier, offset, data}
	// from `yara -s` output — opaque to the backend, just stored/forwarded.
	MatchedStrings string `json:"matched_strings"`

	FileHash string `json:"file_hash"`

	CreatedAt time.Time `json:"created_at"`
}
