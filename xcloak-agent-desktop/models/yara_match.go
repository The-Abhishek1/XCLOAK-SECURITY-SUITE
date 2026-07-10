package models

type YaraMatch struct {
	AgentID int `json:"agent_id"`

	FilePath string `json:"file_path"`

	RuleName string `json:"rule_name"`

	Severity string `json:"severity"`

	Description string `json:"description"`

	// MatchedStrings is a JSON-encoded []YaraMatchedString — the agent
	// marshals it before sending since the backend just stores/forwards it,
	// it never needs to inspect the structure itself.
	MatchedStrings string `json:"matched_strings"`

	FileHash string `json:"file_hash"`
}

// YaraMatchedString is one $identifier hit from `yara -s` output.
type YaraMatchedString struct {
	Identifier string `json:"identifier"`
	Offset     string `json:"offset"`
	Data       string `json:"data"`
}
