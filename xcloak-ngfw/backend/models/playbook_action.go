package models

import (
	"encoding/json"
	"time"
)

type PlaybookAction struct {
	ID int `json:"id"`

	PlaybookID int `json:"playbook_id"`

	StepOrder int `json:"step_order"`

	ActionType string `json:"action_type"`

	Payload json.RawMessage `json:"payload"`

	CreatedAt time.Time `json:"created_at"`
}
