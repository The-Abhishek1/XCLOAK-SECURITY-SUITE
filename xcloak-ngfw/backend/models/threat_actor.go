package models

import "time"

type ThreatActor struct {
	ID               int        `json:"id"`
	TenantID         int        `json:"tenant_id"`
	Name             string     `json:"name"`
	Aliases          []string   `json:"aliases"`
	OriginCountry    string     `json:"origin_country"`
	Motivation       string     `json:"motivation"`
	Sophistication   string     `json:"sophistication"`
	Description      string     `json:"description"`
	TargetedSectors  []string   `json:"targeted_sectors"`
	MitreTechniques  []string   `json:"mitre_techniques"`
	IsBuiltin        bool       `json:"is_builtin"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	// Joined fields
	RecentAlertCount int        `json:"recent_alert_count,omitempty"`
}

type ActorAlertTag struct {
	ID               int       `json:"id"`
	ActorID          int       `json:"actor_id"`
	ActorName        string    `json:"actor_name,omitempty"`
	AlertID          int       `json:"alert_id"`
	TenantID         int       `json:"tenant_id"`
	Confidence       int       `json:"confidence"`
	MatchedTechnique string    `json:"matched_technique"`
	TaggedAt         time.Time `json:"tagged_at"`
}

type PlaybookRecommendation struct {
	ID           int        `json:"id"`
	AlertID      int        `json:"alert_id"`
	TenantID     int        `json:"tenant_id"`
	PlaybookID   int        `json:"playbook_id"`
	PlaybookName string     `json:"playbook_name,omitempty"`
	Score        int        `json:"score"`
	Reason       string     `json:"reason"`
	Executed     bool       `json:"executed"`
	ExecutedBy   string     `json:"executed_by"`
	ExecutedAt   *time.Time `json:"executed_at"`
	CreatedAt    time.Time  `json:"created_at"`
}

type NetworkAnomaly struct {
	ID             int       `json:"id"`
	AgentID        int       `json:"agent_id"`
	Hostname       string    `json:"hostname,omitempty"`
	TenantID       int       `json:"tenant_id"`
	AnomalyType    string    `json:"anomaly_type"`
	DstIP          string    `json:"dst_ip"`
	DstPort        int       `json:"dst_port"`
	Proto          string    `json:"proto"`
	DeviationScore int       `json:"deviation_score"`
	Description    string    `json:"description"`
	IsAcknowledged bool      `json:"is_acknowledged"`
	DetectedAt     time.Time `json:"detected_at"`
}

type NetworkBaseline struct {
	AgentID   int       `json:"agent_id"`
	TenantID  int       `json:"tenant_id"`
	DstIP     string    `json:"dst_ip"`
	DstPort   int       `json:"dst_port"`
	Proto     string    `json:"proto"`
	HitCount  int       `json:"hit_count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}
