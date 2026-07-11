package models

// HeartbeatRequest fields beyond AgentID are all optional (Go zero-value
// defaults) so older agent binaries keep working unchanged.
type HeartbeatRequest struct {
	AgentID       int    `json:"agent_id"`
	Version       string `json:"version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	MemAllocMB    int    `json:"mem_alloc_mb"`
	Goroutines    int    `json:"goroutines"`

	// Linux desktop metrics (from /proc/loadavg, who, /proc/sys/fs/file-nr)
	LoadAvg1m     float64 `json:"load_avg_1m"`
	LoadAvg5m     float64 `json:"load_avg_5m"`
	LoadAvg15m    float64 `json:"load_avg_15m"`
	LoggedInUsers int     `json:"logged_in_users"`
	OpenFDs       int     `json:"open_fds"`

	// Mobile (Android) metrics from PostureCollector
	Platform        string  `json:"platform"`
	BatteryLevel    int     `json:"battery_level"`
	BatteryCharging bool    `json:"battery_charging"`
	NetworkType     string  `json:"network_type"`
	IsRooted        bool    `json:"is_rooted"`
	DeveloperMode   bool    `json:"developer_mode"`
	StorageFreeGB   float64 `json:"storage_free_gb"`
	StorageTotalGB  float64 `json:"storage_total_gb"`
	VPNActive       bool    `json:"vpn_active"`
	SecurityPatch   string  `json:"security_patch"`
}
