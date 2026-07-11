package models

import "time"

type Connection struct {
	ID            int       `json:"id"`
	AgentID       int       `json:"agent_id"`
	Protocol      string    `json:"protocol"`
	LocalAddress  string    `json:"local_address"`
	RemoteAddress string    `json:"remote_address"`
	State         string    `json:"state"`
	CollectedAt   time.Time `json:"collected_at"`
	// Process binding — which process owns this socket.
	// PID is a pointer so 0 and "not reported" are distinguishable.
	PID         *int   `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	ProcessPath string `json:"process_path,omitempty"`
	// GeoIP enrichment fields (populated at ingest by ip_enrich).
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	IsProxy     bool   `json:"is_proxy,omitempty"`
}
