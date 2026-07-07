package agent

import (
	"encoding/json"
	"log/slog"
	"runtime"
	"time"
)

// CurrentVersion is set once at startup from main.Version (see main.go).
var CurrentVersion = "dev"

// startTime anchors the uptime_seconds reported on every heartbeat.
var startTime = time.Now()

// SendHeartbeat reports agent health to the backend. Payload now includes
// CPU load average, logged-in user count, and disk I/O in addition to the
// original version/uptime/memory fields.
func SendHeartbeat(agentID int) {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	data := map[string]any{
		"agent_id":        agentID,
		"version":         CurrentVersion,
		"uptime_seconds":  int64(time.Since(startTime).Seconds()),
		"mem_alloc_mb":    int(mem.Alloc / 1024 / 1024),
		"goroutines":      runtime.NumGoroutine(),
	}

	// Platform-specific enrichment (load avg, logged-in users, disk I/O).
	enrichHeartbeat(data)

	body, _ := json.Marshal(data)
	resp, err := authPost("/api/agents/heartbeat", body)
	if err != nil {
		slog.Warn("heartbeat failed", "err", err)
		return
	}
	defer resp.Body.Close()
}
