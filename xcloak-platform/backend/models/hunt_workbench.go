package models

import "time"

type HuntTemplate struct {
	ID             int       `json:"id"`
	TenantID       int       `json:"tenant_id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	MitreTactic    string    `json:"mitre_tactic"`
	MitreTechnique string    `json:"mitre_technique"`
	KQLQuery       string    `json:"kql_query"`
	Schedule       string    `json:"schedule"`
	IsActive       bool      `json:"is_active"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type HuntRun struct {
	ID          int           `json:"id"`
	TemplateID  *int          `json:"template_id"`
	TenantID    int           `json:"tenant_id"`
	Name        string        `json:"name"`
	KQLQuery    string        `json:"kql_query"`
	Status      string        `json:"status"`
	HitCount    int           `json:"hit_count"`
	Findings    []HuntFinding `json:"findings"`
	Analyst     string        `json:"analyst"`
	Severity    string        `json:"severity"`
	Notes       string        `json:"notes"`
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt *time.Time    `json:"completed_at"`
}

type HuntFinding struct {
	LogID     int    `json:"log_id"`
	AgentID   int    `json:"agent_id"`
	Hostname  string `json:"hostname"`
	Source    string `json:"source"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

type RiskPostureSnapshot struct {
	ID                int         `json:"id"`
	TenantID          int         `json:"tenant_id"`
	Score             int         `json:"score"`
	VulnScore         int         `json:"vuln_score"`
	UEBAScore         int         `json:"ueba_score"`
	AlertScore        int         `json:"alert_score"`
	IOCScore          int         `json:"ioc_score"`
	SnoozedAlertCount int         `json:"snoozed_alert_count"` // not stored; computed fresh per request
	AssetScores       []AssetRisk `json:"asset_scores"`
	SnapshotAt        time.Time   `json:"snapshot_at"`
}

type AssetRisk struct {
	AssetID     int    `json:"asset_id"`
	Hostname    string `json:"hostname"`
	Score       int    `json:"score"`
	TopReason   string `json:"top_reason"`
	Criticality string `json:"criticality"`
}
