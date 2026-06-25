package models

import "time"

// CorrelationMatch is one recorded firing of a correlation rule — the audit
// trail match_count alone never provided (which alert triggered it, which
// incident it opened, how confident the match was).
type CorrelationMatch struct {
	ID             int       `json:"id"`
	RuleID         int       `json:"rule_id"`
	RuleName       string    `json:"rule_name"`
	TenantID       int       `json:"-"`
	AgentID        int       `json:"agent_id"`
	Hostname       string    `json:"hostname"`
	TriggerAlertID *int      `json:"trigger_alert_id,omitempty"`
	IncidentID     *int      `json:"incident_id,omitempty"`
	Confidence     int       `json:"confidence"`
	Detail         string    `json:"detail"`
	MatchedAt      time.Time `json:"matched_at"`
}
