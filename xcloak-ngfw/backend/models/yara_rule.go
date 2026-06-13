package models

import "time"

type YaraRule struct {
	ID int `json:"id"`

	Name string `json:"name"`

	Description string `json:"description"`

	// Raw .yar rule source. Stored as text; the agent fetches all enabled
	// rules and writes each to a temp .yar file before invoking the yara CLI.
	RuleContent string `json:"rule_content"`

	Enabled bool `json:"enabled"`

	CreatedAt time.Time `json:"created_at"`
}
