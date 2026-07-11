package models

import "time"

type Alert struct {
	ID       int `json:"id"`
	AgentID  int `json:"agent_id"`
	TenantID int `json:"tenant_id"`

	Severity    string `json:"severity"`
	RuleName    string `json:"rule_name"`
	Fingerprint string `json:"fingerprint"`

	MitreTactic    string `json:"mitre_tactic"`
	MitreTechnique string `json:"mitre_technique"`
	MitreName      string `json:"mitre_name"`

	LogMessage string    `json:"log_message"`
	CreatedAt  time.Time `json:"created_at"`

	// Lifecycle — zero-valued until set.
	Status         string     `json:"status"`          // open | acknowledged | resolved
	AcknowledgedBy string     `json:"acknowledged_by"` // empty until ack'd
	AcknowledgedAt *time.Time `json:"acknowledged_at"` // nil until ack'd
	Note           string     `json:"note"`            // analyst note

	// AI triage — populated asynchronously after creation.
	AISummary   string     `json:"ai_summary"`
	AIAction    string     `json:"ai_action"`
	AITriagedAt *time.Time `json:"ai_triaged_at"`

	// Suppressed until — non-nil means the rule is muted.
	SuppressedUntil *time.Time `json:"suppressed_until"`

	// Hostname is joined from agents; not a real column.
	Hostname string `json:"hostname,omitempty"`
}
