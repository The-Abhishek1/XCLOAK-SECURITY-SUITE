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

	// ── Live supplementary detail — always computed fresh, never persisted
	// to risk_posture_snapshots (see services.EnrichRiskPostureLiveData) ──
	InternetExposure   InternetExposure   `json:"internet_exposure"`
	MissingPatches     MissingPatches     `json:"missing_patches"`
	UnsupportedOS      []UnsupportedOS    `json:"unsupported_os"`
	Misconfigurations  []Misconfiguration `json:"misconfigurations"`
	UserRisk           []UserRisk         `json:"user_risk"`
	DepartmentRisk     []DepartmentRisk   `json:"department_risk"`
	HighRiskIdentities []HighRiskIdentity `json:"high_risk_identities"`
	HighRiskApps       []HighRiskApp      `json:"high_risk_apps"`
}

type AssetRisk struct {
	AssetID     int    `json:"asset_id"`
	Hostname    string `json:"hostname"`
	Score       int    `json:"score"`
	TopReason   string `json:"top_reason"`
	Criticality string `json:"criticality"`
}

type ExposedHost struct {
	Hostname  string   `json:"hostname"`
	IP        string   `json:"ip"`
	OpenPorts []int    `json:"open_ports"`
	Services  []string `json:"services"`
}

type InternetExposure struct {
	ExposedCount int           `json:"exposed_count"`
	ExposedHosts []ExposedHost `json:"exposed_hosts"`
}

type MissingPatches struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Total    int `json:"total"`
	Overdue  int `json:"overdue"`
}

type UnsupportedOS struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	EOL      string `json:"eol"`
	AgentID  *int   `json:"agent_id"`
}

type Misconfiguration struct {
	ID       int    `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Asset    string `json:"asset"`
	Category string `json:"category"`
}

type UserRisk struct {
	Username     string   `json:"username"`
	RiskScore    int      `json:"risk_score"`
	Flags        []string `json:"flags"`
	FailedLogins int      `json:"failed_logins"`
	OffHours     int      `json:"off_hours"`
	LastSeenIP   string   `json:"last_seen_ip"`
}

type DepartmentRisk struct {
	Name     string `json:"name"`
	Score    int    `json:"score"`
	Users    int    `json:"users"`
	Assets   int    `json:"assets"`
	TopIssue string `json:"top_issue"`
}

type HighRiskIdentity struct {
	Identity       string `json:"identity"`
	IdentityType   string `json:"identity_type"`
	FindingType    string `json:"finding_type"`
	Severity       string `json:"severity"`
	MitreTechnique string `json:"mitre_technique"`
	Description    string `json:"description"`
}

type HighRiskApp struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Risk    string `json:"risk"`
	Reason  string `json:"reason"`
	Assets  int    `json:"assets"`
}
