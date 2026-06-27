package models

// HeartbeatRequest's fields beyond AgentID are all optional (Go zero-value
// defaults) so older agent binaries that only ever sent {"agent_id": N}
// keep working unchanged.
type HeartbeatRequest struct {
	AgentID       int    `json:"agent_id"`
	Version       string `json:"version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	MemAllocMB    int    `json:"mem_alloc_mb"`
	Goroutines    int    `json:"goroutines"`
}
