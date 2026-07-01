package models

import "time"

type Asset struct {
	ID                 int       `json:"id"`
	TenantID           int       `json:"tenant_id"`
	AgentID            *int      `json:"agent_id,omitempty"`
	Name               string    `json:"name"`
	Hostname           string    `json:"hostname"`
	IPAddress          string    `json:"ip_address"`
	AssetType          string    `json:"asset_type"`
	PlatformCategory   string    `json:"platform_category"`
	Owner              string    `json:"owner"`
	BusinessUnit       string    `json:"business_unit"`
	Criticality        string    `json:"criticality"`
	DataClassification string    `json:"data_classification"`
	Environment        string    `json:"environment"`
	Location           string    `json:"location"`
	Tags               []string  `json:"tags"`
	Notes              string    `json:"notes"`
	// joined from agents
	AgentStatus        string    `json:"agent_status,omitempty"`
	RiskScore          int       `json:"risk_score,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type ScheduledReport struct {
	ID         int        `json:"id"`
	TenantID   int        `json:"tenant_id"`
	Name       string     `json:"name"`
	ReportType string     `json:"report_type"`
	Schedule   string     `json:"schedule"`
	Recipients []string   `json:"recipients"`
	Enabled    bool       `json:"enabled"`
	LastSentAt *time.Time `json:"last_sent_at,omitempty"`
	CreatedBy  *int       `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

type ExecutiveMetrics struct {
	MTTRHours         float64                  `json:"mttr_hours"`
	MTTDHours         float64                  `json:"mttd_hours"`
	OpenCases         int                      `json:"open_cases"`
	CriticalCases     int                      `json:"critical_cases"`
	SLAComplianceRate float64                  `json:"sla_compliance_rate"`
	AlertVolume       []DailyCount             `json:"alert_volume"`
	CasesBySeverity   []LabelCount             `json:"cases_by_severity"`
	CasesByPhase      []LabelCount             `json:"cases_by_phase"`
	TopMITRETactics   []LabelCount             `json:"top_mitre_tactics"`
	RiskTrend         []DailyScore             `json:"risk_trend"`
	TotalAssets       int                      `json:"total_assets"`
	CriticalAssets    int                      `json:"critical_assets"`
	OnlineAgents      int                      `json:"online_agents"`
	TotalAlerts       int                      `json:"total_alerts"`
}

type DailyCount struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

type DailyScore struct {
	Date  string  `json:"date"`
	Score float64 `json:"score"`
}

type LabelCount struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}
