package models

import "time"

type Case struct {
	ID              int        `json:"id"`
	TenantID        int        `json:"tenant_id"`
	Title           string     `json:"title"`
	Description     string     `json:"description"`
	Severity        string     `json:"severity"`
	Status          string     `json:"status"`
	Phase           string     `json:"phase"`
	AssignedTo      *int       `json:"assigned_to,omitempty"`
	AssignedToName  string     `json:"assigned_to_name"`
	SLAHours        int        `json:"sla_hours"`
	SLABreachAt     *time.Time `json:"sla_breach_at,omitempty"`
	SLABreached     bool       `json:"sla_breached"`
	MITRETactic     string     `json:"mitre_tactic"`
	MITRETechnique  string     `json:"mitre_technique"`
	RCA             string     `json:"rca"`
	ClosedAt        *time.Time `json:"closed_at,omitempty"`
	AlertCount      int        `json:"alert_count"`
	CommentCount    int        `json:"comment_count"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type CaseComment struct {
	ID        int       `json:"id"`
	CaseID    int       `json:"case_id"`
	UserID    *int      `json:"user_id,omitempty"`
	Username  string    `json:"username"`
	Body      string    `json:"body"`
	IsSystem  bool      `json:"is_system"`
	CreatedAt time.Time `json:"created_at"`
}

type CaseEvidence struct {
	ID           int       `json:"id"`
	CaseID       int       `json:"case_id"`
	EvidenceType string    `json:"evidence_type"`
	ReferenceID  *int      `json:"reference_id,omitempty"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	AddedBy      *int      `json:"added_by,omitempty"`
	AddedByName  string    `json:"added_by_name"`
	CreatedAt    time.Time `json:"created_at"`
}
