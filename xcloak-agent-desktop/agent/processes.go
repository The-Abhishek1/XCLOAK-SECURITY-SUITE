//go:build !windows

package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"xcloak-agent-desktop/models"
)

// CollectProcesses snapshots every running process and ships rich telemetry
// to the server in one POST. Fields captured per process:
//   - pid, ppid       — from ps -eo pid,ppid
//   - name (comm)     — short executable name
//   - cmdline         — full argv from /proc/<pid>/cmdline
//   - username        — owning user from ps -eo user
//   - cpu%,mem%       — from ps -eo pcpu,pmem
//   - exe_path        — resolved via /proc/<pid>/exe symlink
//
// The extra fields — especially cmdline — are what make detections like
// "powershell -EncodedCommand", "bash -c /dev/tcp/...", and "python -c exec(...)"
// possible at the process level rather than only from log heuristics.
func CollectProcesses(agentID int) {

	// ── Snapshot via ps ──────────────────────────────────────────
	// pid ppid user %cpu %mem comm → six fixed-width fields; comm is last
	// so spaces in username don't break parsing.
	// We use -ww to prevent ps from truncating long command lines in comm.
	out, err := runPS()
	if err != nil {
		fmt.Println("[collector] processes: ps failed:", err)
		return
	}

	// Build a pid→Process map from ps output.
	byPID := parsePS(agentID, out)

	// ── Enrich with /proc/<pid>/cmdline ─────────────────────────
	// ps comm is truncated to 15 chars; /proc/<pid>/cmdline gives the full
	// argument vector. We do this per-process so missing /proc entries
	// (e.g. a process that died between ps and now) are skipped gracefully.
	for pid, p := range byPID {
		p.Cmdline = readCmdline(pid)
		p.ExePath  = readExePath(pid)
		byPID[pid] = p
	}

	// ── Flatten to slice and ship ────────────────────────────────
	processes := make([]models.Process, 0, len(byPID))
	for _, p := range byPID {
		processes = append(processes, p)
	}

	body, _ := json.Marshal(processes)
	resp, err := authPost("/api/agents/processes", body)
	if err != nil {
		fmt.Println("[collector] processes: send failed:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("[collector] processes: sent %d\n", len(processes))
}

// runPS executes ps and returns its raw output.
func runPS() (string, error) {
	// -e  : all processes
	// -o  : custom format
	// -ww : unlimited line width (prevents comm truncation in some ps versions)
	cmd := buildPSCommand()
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// parsePS converts ps output lines into a pid→Process map.
func parsePS(agentID int, raw string) map[int]models.Process {
	result := make(map[int]models.Process)

	scanner := bufio.NewScanner(strings.NewReader(raw))
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // skip header
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Format: pid ppid user cpu mem comm
		// Fields are separated by whitespace; comm may contain spaces on some
		// systems but we only need up to field 5 for the ps fields.
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		pid, _  := strconv.Atoi(fields[0])
		ppid, _ := strconv.Atoi(fields[1])
		user    := fields[2]
		cpu     := fields[3]
		mem     := fields[4]
		name    := strings.Join(fields[5:], " ") // comm can be multi-word

		if pid == 0 {
			continue
		}

		result[pid] = models.Process{
			AgentID:    agentID,
			PID:        pid,
			PPID:       ppid,
			Name:       name,
			Username:   user,
			CPUPercent: cpu,
			MemPercent: mem,
		}
	}
	return result
}

// readCmdline reads the full command line for a process from /proc/<pid>/cmdline.
// The kernel stores argv as NUL-separated bytes; we replace NUL with space.
// Returns "" if the file is unreadable (kernel threads, permission denied, etc.)
func readCmdline(pid int) string {
	path := fmt.Sprintf("/proc/%d/cmdline", pid)
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return ""
	}
	// Replace NUL separators with spaces and trim trailing whitespace/NUL.
	for i, b := range data {
		if b == 0 {
			data[i] = ' '
		}
	}
	return strings.TrimSpace(string(data))
}

// readExePath resolves /proc/<pid>/exe to the real binary path.
// Returns "" for kernel threads or if permission is denied.
func readExePath(pid int) string {
	link := fmt.Sprintf("/proc/%d/exe", pid)
	target, err := os.Readlink(link)
	if err != nil {
		return ""
	}
	return target
}
