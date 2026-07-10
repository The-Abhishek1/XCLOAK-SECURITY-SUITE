package models

import "time"

type ITDRFinding struct {
	ID             int        `json:"id"`
	TenantID       int        `json:"tenant_id"`
	FindingType    string     `json:"finding_type"`
	Severity       string     `json:"severity"`
	Identity       string     `json:"identity"`
	IdentityType   string     `json:"identity_type"`
	SourceIP       string     `json:"source_ip,omitempty"`
	Description    string     `json:"description"`
	Evidence       any        `json:"evidence"`
	MITRETechnique string     `json:"mitre_technique,omitempty"`
	Status         string     `json:"status"`
	AgentID        *int       `json:"agent_id,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	DedupKey       string     `json:"dedup_key"`
}
