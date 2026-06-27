package models

import (
	"encoding/json"
	"time"
)

// AITriageResult is the structured JSON the LLM returns for alert triage.
type AITriageResult struct {
	Summary        string   `json:"summary"`
	Severity       string   `json:"severity"`
	RecommendedAction string `json:"recommended_action"`
	FalsePositive  bool     `json:"false_positive"`
	MitreTechnique string   `json:"mitre_technique"`
	Tags           []string `json:"tags"`
}

// AIIncidentSummary is what the LLM returns for incident summarization.
type AIIncidentSummary struct {
	Summary         string   `json:"summary"`
	Timeline        []string `json:"timeline"`
	RootCauseHint   string   `json:"root_cause_hint"`
	RecommendedSteps []string `json:"recommended_steps"`
}

// ChatMessage represents a single turn in an AI chat session.
type ChatMessage struct {
	Role      string    `json:"role"`    // "user" or "assistant"
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
}

// AIChatSession stores the conversation history for one user session.
type AIChatSession struct {
	ID        int               `json:"id"`
	Username  string            `json:"username"`
	Messages  json.RawMessage   `json:"messages"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// AnomalyFinding is a behavioural anomaly detected by the AI or behavioral engine.
type AnomalyFinding struct {
	ID           int             `json:"id"`
	AgentID      int             `json:"agent_id"`
	FindingType  string          `json:"finding_type"`
	Description  string          `json:"description"`
	Severity     string          `json:"severity"`
	Score        int             `json:"score"`        // 0-100 composite risk score
	Acknowledged bool            `json:"acknowledged"` // operator dismissed this finding
	Source       string          `json:"source"`       // "ai" or "behavioral"
	RawContext   json.RawMessage `json:"raw_context"`
	CreatedAt    time.Time       `json:"created_at"`
}

// AgentAnomalyScore is one 5-minute behavioral scoring snapshot.
type AgentAnomalyScore struct {
	ID         int             `json:"id"`
	AgentID    int             `json:"agent_id"`
	TenantID   int             `json:"tenant_id"`
	Score      int             `json:"score"`
	Components json.RawMessage `json:"components"`
	ScoredAt   time.Time       `json:"scored_at"`
}

// AgentBaseline is a per-hour-of-week behavioral baseline for one agent.
type AgentBaseline struct {
	AgentID      int       `json:"agent_id"`
	HourOfWeek   int       `json:"hour_of_week"`
	AvgLogCount  float64   `json:"avg_log_count"`
	AvgLoginFail float64   `json:"avg_login_fail"`
	AvgConnCount float64   `json:"avg_conn_count"`
	SampleCount  int       `json:"sample_count"`
	UpdatedAt    time.Time `json:"updated_at"`
}
