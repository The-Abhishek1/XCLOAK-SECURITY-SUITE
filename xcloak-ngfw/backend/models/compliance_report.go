package models

import (
	"encoding/json"
	"time"
)

type ComplianceReport struct {
	ID          int             `json:"id"`
	Title       string          `json:"title"`
	ReportType  string          `json:"report_type"`
	GeneratedBy string          `json:"generated_by"`
	Summary     json.RawMessage `json:"summary"`
	CreatedAt   time.Time       `json:"created_at"`
}

// ComplianceSummary is the structured body stored in Summary JSONB.
type ComplianceSummary struct {
	TotalAgents      int                      `json:"total_agents"`
	OnlineAgents     int                      `json:"online_agents"`
	TotalAlerts      int                      `json:"total_alerts"`
	CriticalAlerts   int                      `json:"critical_alerts"`
	OpenIncidents    int                      `json:"open_incidents"`
	TotalVulns       int                      `json:"total_vulns"`
	CriticalVulns    int                      `json:"critical_vulns"`
	TotalIOCs        int                      `json:"total_iocs"`
	SigmaRules       int                      `json:"sigma_rules"`
	YaraRules        int                      `json:"yara_rules"`
	TopRiskAgents    []AgentRiskEntry         `json:"top_risk_agents"`
	VulnsBySeverity  map[string]int           `json:"vulns_by_severity"`
	AlertsBySeverity map[string]int           `json:"alerts_by_severity"`
	RecentIncidents  []IncidentSummaryEntry   `json:"recent_incidents"`
}

type AgentRiskEntry struct {
	AgentID   int    `json:"agent_id"`
	Hostname  string `json:"hostname"`
	RiskScore int    `json:"risk_score"`
	RiskLevel string `json:"risk_level"`
}

type IncidentSummaryEntry struct {
	ID       int    `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
}
