package models

import "time"

type Agent struct {
	ID        int       `json:"id"`
	MachineID string    `json:"machine_id"` // stable hardware fingerprint
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	IPAddress string    `json:"ip_address"`
	Status    string    `json:"status"`
	Token     string    `json:"token,omitempty"` // only sent on first registration
	TenantID  int       `json:"tenant_id"`
	LastSeen  time.Time `json:"last_seen"`
	CreatedAt time.Time `json:"created_at"`

	// Self-reported on every heartbeat (see agent/heartbeat.go) — absent/zero
	// for agents running an older binary that doesn't send these yet.
	Version       string `json:"version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	MemAllocMB    int    `json:"mem_alloc_mb"`
	Goroutines    int    `json:"goroutines"`
}
