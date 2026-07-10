package models

import "time"

type PlaybookExecution struct {
	ID            int       `json:"id"`
	PlaybookID    int       `json:"playbook_id"`
	AgentID       int       `json:"agent_id"`
	AlertRule     string    `json:"alert_rule"`
	ActionType    string    `json:"action_type"`
	Status        string    `json:"status"`
	ErrorDetail   string    `json:"error_detail"`
	TaskID        int       `json:"task_id"`
	TenantID      int       `json:"tenant_id"`
	OverallStatus string    `json:"overall_status"`
	StepsTotal    int       `json:"steps_total"`
	StepsOK       int       `json:"steps_ok"`
	StepsFailed   int       `json:"steps_failed"`
	StepsSkipped  int       `json:"steps_skipped"`
	DurationMs    int       `json:"duration_ms"`
	CreatedAt     time.Time `json:"created_at"`
}
