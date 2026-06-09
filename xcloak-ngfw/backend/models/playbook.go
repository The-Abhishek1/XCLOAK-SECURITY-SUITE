package models

import "time"

type Playbook struct {
	ID int `json:"id"`

	Name string `json:"name"`

	TriggerType string `json:"trigger_type"`

	ActionType string `json:"action_type"`

	Enabled bool `json:"enabled"`

	CreatedAt time.Time `json:"created_at"`
}
