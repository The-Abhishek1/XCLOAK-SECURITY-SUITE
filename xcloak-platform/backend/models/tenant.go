package models

import "time"

type Tenant struct {
	ID          int       `json:"id"`
	WorkspaceID string    `json:"workspace_id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`

	// UserCount is only populated by GetTenants — not a real column.
	UserCount int `json:"user_count,omitempty"`
}

type TenantSMTPConfig struct {
	TenantID  int    `json:"tenant_id"`
	Host      string `json:"host"`
	Port      string `json:"port"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	FromAddr  string `json:"from_addr"`
	TLS       bool   `json:"tls"`
}
