package models

import "time"

type FirewallRule struct {
	ID            int        `json:"id"`
	Name          string     `json:"name"`
	Description   string     `json:"description"`
	GroupName     string     `json:"group_name"`
	SourceIP      string     `json:"source_ip"`
	DestinationIP string     `json:"destination_ip"`
	Protocol      string     `json:"protocol"`
	Port          int        `json:"port"`
	// PortRange replaces/extends Port: "80", "8000-9000", "80,443,8080"
	PortRange     string     `json:"port_range"`
	Direction     string     `json:"direction"`     // "in" | "out" | "both"
	LogEnabled    bool       `json:"log_enabled"`
	LogPrefix     string     `json:"log_prefix"`
	Action        string     `json:"action"`
	Enabled       bool       `json:"enabled"`
	Priority      int        `json:"priority"`
	Tags          []string   `json:"tags"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	CreatedBy     string     `json:"created_by"`
	UpdatedBy     string     `json:"updated_by"`
	UpdatedAt     time.Time  `json:"updated_at"`
	HitCount      int64      `json:"hit_count"`
	SyncedAt      *time.Time `json:"synced_at"`
}
