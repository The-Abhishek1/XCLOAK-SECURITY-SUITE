package models

import "time"

type User struct {
	ID           int        `json:"id"`
	Username     string     `json:"username"`
	Email        string     `json:"email"`
	Password     string     `json:"password,omitempty"`
	PasswordHash string     `json:"-"`
	Role         string     `json:"role"`
	TenantID     int        `json:"tenant_id"`
	IsPlatformAdmin bool    `json:"is_platform_admin"`
	IsActive     bool       `json:"is_active"`
	LastLogin    *time.Time `json:"last_login"`
	CreatedAt    *time.Time `json:"created_at"`
}
