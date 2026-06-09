package models

import "time"

type PlaybookExecution struct {
	ID int `json:"id"`

	PlaybookID int `json:"playbook_id"`

	AgentID int `json:"agent_id"`

	AlertRule string `json:"alert_rule"`

	ActionType string `json:"action_type"`

	Status string `json:"status"`

	CreatedAt time.Time `json:"created_at"`
}
