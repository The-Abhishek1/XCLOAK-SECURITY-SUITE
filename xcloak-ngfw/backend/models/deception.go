package models

import "time"

type CanaryToken struct {
	ID            int        `json:"id" db:"id"`
	TenantID      int        `json:"tenant_id" db:"tenant_id"`
	TokenType     string     `json:"token_type" db:"token_type"`
	Name          string     `json:"name" db:"name"`
	TokenValue    string     `json:"token_value" db:"token_value"`
	Description   string     `json:"description" db:"description"`
	DeployedTo    string     `json:"deployed_to" db:"deployed_to"`
	CreatedBy     string     `json:"created_by" db:"created_by"`
	AlertOnTrip   bool       `json:"alert_on_trip" db:"alert_on_trip"`
	IsActive      bool       `json:"is_active" db:"is_active"`
	TripCount     int        `json:"trip_count" db:"trip_count"`
	LastTrippedAt *time.Time `json:"last_tripped_at" db:"last_tripped_at"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
}

type CanaryTrip struct {
	ID        int            `json:"id"`
	TokenID   int            `json:"token_id"`
	TenantID  int            `json:"tenant_id"`
	SourceIP  string         `json:"source_ip"`
	UserAgent string         `json:"user_agent"`
	Method    string         `json:"method"`
	ExtraData map[string]any `json:"extra_data"`
	TrippedAt time.Time      `json:"tripped_at"`
}

type Honeyport struct {
	ID            int       `json:"id"`
	TenantID      int       `json:"tenant_id"`
	AgentID       int       `json:"agent_id"`
	Port          int       `json:"port"`
	Protocol      string    `json:"protocol"`
	Description   string    `json:"description"`
	AlertSeverity string    `json:"alert_severity"`
	IsActive      bool      `json:"is_active"`
	CreatedAt     time.Time `json:"created_at"`
	Hostname      string    `json:"hostname,omitempty"`
}
