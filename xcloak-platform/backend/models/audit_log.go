package models

import "time"

type AuditLog struct {
	ID        int       `json:"id"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
}
