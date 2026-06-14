package models

import (
	"encoding/json"
	"time"
)

type HuntQuery struct {
	ID          int        `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	QueryType   string     `json:"query_type"`
	QueryText   string     `json:"query_text"`
	CreatedBy   string     `json:"created_by"`
	HitCount    int        `json:"hit_count"`
	LastRunAt   *time.Time `json:"last_run_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

type HuntResult struct {
	ID      int             `json:"id"`
	QueryID int             `json:"query_id"`
	AgentID int             `json:"agent_id"`
	Result  json.RawMessage `json:"result"`
	FoundAt time.Time       `json:"found_at"`
}

type HuntRunResponse struct {
	QueryID  int           `json:"query_id"`
	Hits     int           `json:"hits"`
	Duration string        `json:"duration_ms"`
	Results  []HuntResult  `json:"results"`
}

type ScheduledTask struct {
	ID         int        `json:"id"`
	Name       string     `json:"name"`
	TaskType   string     `json:"task_type"`
	AgentIDs   []int      `json:"agent_ids"`
	CronExpr   string     `json:"cron_expr"`
	Payload    json.RawMessage `json:"payload"`
	Enabled    bool       `json:"enabled"`
	LastRunAt  *time.Time `json:"last_run_at"`
	NextRunAt  *time.Time `json:"next_run_at"`
	RunCount   int        `json:"run_count"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
}
