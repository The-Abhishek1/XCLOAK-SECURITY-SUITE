package models

import "time"

type LogSource struct {
	ID          int        `json:"id"`
	TenantID    int        `json:"tenant_id"`
	Name        string     `json:"name"`
	SourceType  string     `json:"source_type"` // "syslog" | "http"
	IPAddress   string     `json:"ip_address,omitempty"`
	APIKeyHint  string     `json:"api_key_hint,omitempty"`
	Format      string     `json:"format"`
	DeviceType  string     `json:"device_type,omitempty"`
	AgentID     *int       `json:"agent_id,omitempty"`
	Enabled     bool       `json:"enabled"`
	LastEvent   *time.Time `json:"last_event,omitempty"`
	EventCount  int64      `json:"event_count"`
	CreatedAt   time.Time  `json:"created_at"`

	// Only returned on creation, never stored in DB.
	APIKey string `json:"api_key,omitempty"`
}
