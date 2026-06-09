package models

import (
	"encoding/json"
	"time"
)

type AgentTask struct {
	ID          int             `json:"id"`
	AgentID     int             `json:"agent_id"`
	TaskType    string          `json:"task_type"`
	Payload     json.RawMessage `json:"payload"`
	Status      string          `json:"status"`
	Result      *string         `json:"result"`
	CreatedAt   time.Time       `json:"created_at"`
	CompletedAt *time.Time      `json:"completed_at"`
}
