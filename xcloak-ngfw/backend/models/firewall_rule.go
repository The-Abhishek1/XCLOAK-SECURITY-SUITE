package models

import "time"

type FirewallRule struct {
	ID            int        `json:"id"`
	Name          string     `json:"name"`
	SourceIP      string     `json:"source_ip"`
	DestinationIP string     `json:"destination_ip"`
	Protocol      string     `json:"protocol"`
	Port          int        `json:"port"`
	Action        string     `json:"action"`
	Enabled       bool       `json:"enabled"`
	Priority      int        `json:"priority"`
	SyncedAt      *time.Time `json:"synced_at"`
}
