package models

import "time"

type Alert struct {
	ID          int    `json:"id"`
	AgentID     int    `json:"agent_id"`
	TenantID    int    `json:"tenant_id"`
	Severity    string `json:"severity"`
	RuleName    string `json:"rule_name"`
	Fingerprint string `json:"fingerprint"`

	MitreTactic    string `json:"mitre_tactic"`
	MitreTechnique string `json:"mitre_technique"`
	MitreName      string `json:"mitre_name"`

	LogMessage string    `json:"log_message"`
	CreatedAt  time.Time `json:"created_at"`
}
