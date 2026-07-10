//go:build !windows

package agent

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// enrichHeartbeat adds Linux-specific telemetry to the heartbeat payload.
func enrichHeartbeat(data map[string]any) {
	// CPU load averages from /proc/loadavg: "load1 load5 load15 rq/total lastpid"
	if raw, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) >= 3 {
			if v, err := strconv.ParseFloat(fields[0], 64); err == nil {
				data["load_avg_1m"] = v
			}
			if v, err := strconv.ParseFloat(fields[1], 64); err == nil {
				data["load_avg_5m"] = v
			}
			if v, err := strconv.ParseFloat(fields[2], 64); err == nil {
				data["load_avg_15m"] = v
			}
		}
	}

	// Count currently logged-in users via `who`.
	if out, err := exec.Command("who").Output(); err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		count := 0
		for _, l := range lines {
			if strings.TrimSpace(l) != "" {
				count++
			}
		}
		data["logged_in_users"] = count
	}

	// Open file descriptor count from /proc/sys/fs/file-nr: "open alloc max"
	if raw, err := os.ReadFile("/proc/sys/fs/file-nr"); err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) >= 1 {
			if v, err := strconv.Atoi(fields[0]); err == nil {
				data["open_fds"] = v
			}
		}
	}
}
