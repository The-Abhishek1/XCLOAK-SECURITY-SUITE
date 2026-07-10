package models

import (
	"encoding/json"
	"time"
)

type ForensicCollection struct {
	ID            int        `json:"id"`
	TenantID      int        `json:"tenant_id"`
	IncidentID    *int       `json:"incident_id"`
	AgentID       *int       `json:"agent_id"`
	AgentHostname string     `json:"agent_hostname,omitempty"`
	Label         string     `json:"label"`
	Status        string     `json:"status"`
	ArtifactTypes []string   `json:"artifact_types"`
	TriggeredBy   string     `json:"triggered_by"`
	StartedAt     *time.Time `json:"started_at"`
	CompletedAt   *time.Time `json:"completed_at"`
	CreatedAt     time.Time  `json:"created_at"`
	ArtifactCount int        `json:"artifact_count,omitempty"`
}

type ForensicArtifact struct {
	ID           int             `json:"id"`
	CollectionID int             `json:"collection_id"`
	TenantID     int             `json:"tenant_id"`
	AgentID      int             `json:"agent_id"`
	ArtifactType string          `json:"artifact_type"`
	Data         json.RawMessage `json:"data"`
	ItemCount    int             `json:"item_count"`
	CollectedAt  time.Time       `json:"collected_at"`
}

// ForensicTimelineEvent is a unified event for the incident forensic timeline.
type ForensicTimelineEvent struct {
	Time      time.Time `json:"time"`
	Source    string    `json:"source"` // alert, log, connection, artifact
	EventType string    `json:"event_type"`
	Summary   string    `json:"summary"`
	Severity  string    `json:"severity,omitempty"`
	AgentID   int       `json:"agent_id,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	RawID     int       `json:"raw_id,omitempty"`
}

// AlertCluster is a group of related alerts.
type AlertCluster struct {
	ID             int       `json:"id"`
	TenantID       int       `json:"tenant_id"`
	ClusterKey     string    `json:"cluster_key"`
	MitreTechnique string    `json:"mitre_technique"`
	RuleName       string    `json:"rule_name"`
	AlertCount     int       `json:"alert_count"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	AutoIncidentID *int      `json:"auto_incident_id"`
	Status         string    `json:"status"`
	AlertIDs       []int     `json:"alert_ids,omitempty"`
}

// FrameworkControl represents a single control in a security framework.
type FrameworkControl struct {
	ControlRef  string `json:"control_ref"` // e.g. "CIS-4.1", "NIST-DE.CM-1"
	Framework   string `json:"framework"`   // CIS, NIST, PCI-DSS, ISO27001
	Title       string `json:"title"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Severity    string `json:"severity"` // critical, high, medium, low
}

// ControlCoverage is the per-tenant coverage state for one control.
type ControlCoverage struct {
	ControlRef     string `json:"control_ref"`
	Framework      string `json:"framework"`
	Title          string `json:"title"`
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	Status         string `json:"status"`        // covered, partial, gap
	CoverageScore  int    `json:"coverage_score"` // 0-100
	EvidenceCount  int    `json:"evidence_count"`
	EvidenceSource string `json:"evidence_source"` // sigma_rules, alerts, vulns, firewall, nba
	Notes          string `json:"notes"`
}

// FrameworkAssessment is a full assessment of a framework for a tenant.
type FrameworkAssessment struct {
	Framework     string            `json:"framework"`
	TotalControls int               `json:"total_controls"`
	Covered       int               `json:"covered"`
	Partial       int               `json:"partial"`
	Gaps          int               `json:"gaps"`
	OverallScore  int               `json:"overall_score"` // 0-100
	Controls      []ControlCoverage `json:"controls"`
}
