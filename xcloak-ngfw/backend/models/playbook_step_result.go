package models

import "time"

type PlaybookStepResult struct {
	ID            int        `json:"id"`
	ExecutionID   int        `json:"execution_id"`
	StepOrder     int        `json:"step_order"`
	ActionType    string     `json:"action_type"`
	ConditionExpr string     `json:"condition_expr"`
	Status        string     `json:"status"`
	Output        string     `json:"output"`
	ErrorDetail   string     `json:"error_detail"`
	RetriesUsed   int        `json:"retries_used"`
	StartedAt     time.Time  `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at"`
}
