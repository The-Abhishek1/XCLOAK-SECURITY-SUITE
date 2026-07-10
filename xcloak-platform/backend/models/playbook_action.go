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

	// Conditional branching (migration 000045)
	StepName      string `json:"step_name"`       // label for this step; used as goto target
	GotoOnSuccess string `json:"goto_on_success"` // step_name to jump to on success; "end" to stop
	GotoOnFailure string `json:"goto_on_failure"` // step_name to jump to on failure; "end" to stop
	StopOnFailure bool   `json:"stop_on_failure"` // abort the entire playbook if this step fails
	LoopOver      string `json:"loop_over"`       // ctx key holding comma-separated items; step runs once per item
}
