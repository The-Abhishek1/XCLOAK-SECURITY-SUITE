//go:build windows

package agent

import (
	"encoding/json"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"

	"xcloak-agent-desktop/models"
)

// CollectConnections on Windows uses netstat -ano (includes PID column) and
// resolves PID → process name via tasklist.
func CollectConnections(agentID int) {
	pidNames := buildWindowsPIDNames()

	out, err := exec.Command("netstat", "-ano").Output()
	if err != nil {
		slog.Error("CollectConnections: netstat failed", "err", err)
		return
	}

	var connections []models.Connection
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Proto") || strings.HasPrefix(line, "Active") {
			continue
		}
		// Format: Proto  Local Address  Foreign Address  State  PID
		// UDP:    Proto  Local Address  Foreign Address  PID  (no State)
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		proto := fields[0]
		local := fields[1]
		remote := fields[2]
		state := ""
		pidStr := ""

		if strings.HasPrefix(strings.ToUpper(proto), "UDP") {
			// UDP: fields = [UDP, local, remote, pid]
			pidStr = fields[3]
			state = "STATELESS"
		} else if len(fields) >= 5 {
			state = fields[3]
			pidStr = fields[4]
		} else {
			state = fields[3]
		}

		pid, _ := strconv.Atoi(strings.TrimSpace(pidStr))
		conn := models.Connection{
			AgentID:       agentID,
			Protocol:      proto,
			LocalAddress:  local,
			RemoteAddress: remote,
			State:         state,
			PID:           pid,
		}
		if pid > 0 {
			conn.ProcessName = pidNames[pid]
		}
		connections = append(connections, conn)
	}

	body, _ := json.Marshal(connections)
	resp, err := authPost("/api/agents/connections", body)
	if err != nil {
		slog.Error("CollectConnections: send failed", "err", err)
		return
	}
	defer resp.Body.Close()
	slog.Info("connections sent", "count", len(connections))
}

// buildWindowsPIDNames runs tasklist /fo csv and returns a PID→name map.
func buildWindowsPIDNames() map[int]string {
	m := make(map[int]string)
	out, err := exec.Command("tasklist", "/fo", "csv", "/nh").Output()
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// CSV: "Image Name","PID","Session Name","Session#","Mem Usage"
		fields := splitCSV(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.Trim(fields[0], "\"")
		pidStr := strings.Trim(fields[1], "\"")
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		m[pid] = name
	}
	return m
}
