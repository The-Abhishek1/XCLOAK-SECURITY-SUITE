package models

import "encoding/json"

type AgentTask struct {
	ID       int             `json:"id"`
	AgentID  int             `json:"agent_id"`
	TaskType string          `json:"task_type"`
	Payload  json.RawMessage `json:"payload"`
	Status   string          `json:"status"`
}

type TaskResult struct {
	TaskID int    `json:"task_id"`
	Result string `json:"result"`
}
