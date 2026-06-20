package models

import "time"

type Tenant struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`

	// UserCount is only populated by GetTenants — not a real column.
	UserCount int `json:"user_count,omitempty"`
}
