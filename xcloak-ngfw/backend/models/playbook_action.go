package models

import (
	"encoding/json"
	"time"
)

type PlaybookAction struct {
	ID             int             `json:"id"`
	PlaybookID     int             `json:"playbook_id"`
	StepOrder      int             `json:"step_order"`
	ActionType     string          `json:"action_type"`
	Payload        json.RawMessage `json:"payload"`
	ConditionExpr  string          `json:"condition_expr"`
	MaxRetries     int             `json:"max_retries"`
	RetryDelaySecs int             `json:"retry_delay_secs"`
	RunParallel    bool            `json:"run_parallel"`
	TimeoutSeconds int             `json:"timeout_seconds"`
	TenantID       int             `json:"tenant_id"`
	CreatedAt      time.Time       `json:"created_at"`
}
