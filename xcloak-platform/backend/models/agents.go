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

	// Self-reported on every heartbeat — absent/zero for older agent binaries.
	Version       string `json:"version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	MemAllocMB    int    `json:"mem_alloc_mb"`
	Goroutines    int    `json:"goroutines"`

	// Derived from agents.os via ClassifyOS().
	PlatformCategory string `json:"platform_category"`

	// Linux desktop metrics (from /proc/loadavg, who, /proc/sys/fs/file-nr)
	LoadAvg1m     *float64 `json:"load_avg_1m,omitempty"`
	LoadAvg5m     *float64 `json:"load_avg_5m,omitempty"`
	LoadAvg15m    *float64 `json:"load_avg_15m,omitempty"`
	LoggedInUsers *int     `json:"logged_in_users,omitempty"`
	OpenFDs       *int     `json:"open_fds,omitempty"`

	// Mobile (Android) posture metrics
	BatteryLevel    *int     `json:"battery_level,omitempty"`
	BatteryCharging *bool    `json:"battery_charging,omitempty"`
	NetworkType     *string  `json:"network_type,omitempty"`
	IsRooted        *bool    `json:"is_rooted,omitempty"`
	DeveloperMode   *bool    `json:"developer_mode,omitempty"`
	StorageFreeGB   *float64 `json:"storage_free_gb,omitempty"`
	StorageTotalGB  *float64 `json:"storage_total_gb,omitempty"`
	VPNActive       *bool    `json:"vpn_active,omitempty"`
	SecurityPatch   *string  `json:"security_patch,omitempty"`

	// Server-computed fields — populated in list endpoints, never sent by agents.
	OpenAlertCount int  `json:"open_alert_count,omitempty"`
	RiskScore      *int `json:"risk_score,omitempty"`
}
