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

// AnomalyFinding is a behavioural anomaly detected by the AI layer.
type AnomalyFinding struct {
	ID          int             `json:"id"`
	AgentID     int             `json:"agent_id"`
	FindingType string          `json:"finding_type"`
	Description string          `json:"description"`
	Severity    string          `json:"severity"`
	RawContext  json.RawMessage `json:"raw_context"`
	CreatedAt   time.Time       `json:"created_at"`
}
