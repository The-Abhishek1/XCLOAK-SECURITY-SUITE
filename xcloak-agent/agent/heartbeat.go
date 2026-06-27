package agent

import (
	"encoding/json"
	"fmt"
	"runtime"
	"time"
)

// CurrentVersion is set once at startup from main.Version (see main.go) —
// read here by both the heartbeat payload below and the self-update checker.
var CurrentVersion = "dev"

// startTime anchors the uptime_seconds reported on every heartbeat.
var startTime = time.Now()

// SendHeartbeat pings the server to keep the agent marked online, and now
// also reports basic self-health: version, uptime, and Go runtime memory/
// goroutine counts — previously a heartbeat was bare {"agent_id": N}, so
// the backend's "agent health" view was entirely reconstructed from
// heartbeat timing and task outcomes with no signal from the agent's
// actual own state. Uses authPost so the heartbeat endpoint can require
// agent auth.
func SendHeartbeat(agentID int) {

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	data := map[string]any{
		"agent_id":       agentID,
		"version":        CurrentVersion,
		"uptime_seconds": int64(time.Since(startTime).Seconds()),
		"mem_alloc_mb":   int(mem.Alloc / 1024 / 1024),
		"goroutines":     runtime.NumGoroutine(),
	}
	body, _ := json.Marshal(data)

	resp, err := authPost("/api/agents/heartbeat", body)
	if err != nil {
		fmt.Println("Heartbeat failed:", err)
		return
	}
	defer resp.Body.Close()
}
