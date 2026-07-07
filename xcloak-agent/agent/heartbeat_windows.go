//go:build windows

package agent

import (
	"os/exec"
	"strconv"
	"strings"
)

// enrichHeartbeat adds Windows-specific telemetry to the heartbeat payload.
func enrichHeartbeat(data map[string]any) {
	// Logged-in users via quser (query user) — available on all Windows Server
	// editions and Windows 10/11 Pro+.
	if out, err := exec.Command("query", "user").Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		count := 0
		for _, l := range lines[1:] { // skip header
			if strings.TrimSpace(l) != "" {
				count++
			}
		}
		data["logged_in_users"] = count
	}

	// CPU load — use wmic cpu get LoadPercentage
	if out, err := exec.Command("wmic", "cpu", "get", "LoadPercentage", "/value").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "LoadPercentage=") {
				v, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "LoadPercentage=")))
				data["cpu_load_pct"] = v
				break
			}
		}
	}
}
