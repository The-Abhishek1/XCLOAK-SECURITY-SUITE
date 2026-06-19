//go:build windows

package agent

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"xcloak-agent/models"
)

// CollectProcesses on Windows uses WMIC to capture rich process telemetry:
// PID, ParentProcessId, Name, CommandLine, and the owning user.
//
// WMIC is available on all Windows versions back to XP. For Windows 11 22H2+
// where WMIC is deprecated, we fall back to PowerShell Get-CimInstance.
func CollectProcesses(agentID int) {

	processes, err := collectViaWMIC(agentID)
	if err != nil || len(processes) == 0 {
		// WMIC unavailable (Win11 22H2+ or restricted policy) — try PowerShell.
		fmt.Println("[collector] processes: WMIC failed, trying PowerShell CIM")
		processes = collectViaCIM(agentID)
	}

	if len(processes) == 0 {
		fmt.Println("[collector] processes: no processes collected")
		return
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

// collectViaWMIC uses `wmic process get` to enumerate processes with rich fields.
func collectViaWMIC(agentID int) ([]models.Process, error) {

	out, err := exec.Command(
		"wmic", "process", "get",
		"ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath",
		"/FORMAT:CSV",
	).Output()
	if err != nil {
		return nil, err
	}

	var processes []models.Process
	lines := strings.Split(string(out), "\n")

	// WMIC CSV: Node,CommandLine,ExecutablePath,Name,ParentProcessId,ProcessId
	// Header row varies — find it first.
	headerIdx := -1
	var headers []string
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "processid") {
			headers = splitCSV(line)
			headerIdx = i
			break
		}
	}
	if headerIdx < 0 {
		return nil, fmt.Errorf("WMIC: header not found")
	}

	// Build column index map.
	colIdx := make(map[string]int)
	for i, h := range headers {
		colIdx[strings.TrimSpace(strings.ToLower(h))] = i
	}

	for _, line := range lines[headerIdx+1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := splitCSV(line)
		if len(fields) < len(headers) {
			continue
		}

		get := func(key string) string {
			i, ok := colIdx[key]
			if !ok || i >= len(fields) {
				return ""
			}
			return strings.TrimSpace(fields[i])
		}

		pid  := atoiSafe(get("processid"))
		ppid := atoiSafe(get("parentprocessid"))
		if pid == 0 {
			continue
		}

		processes = append(processes, models.Process{
			AgentID: agentID,
			PID:     pid,
			PPID:    ppid,
			Name:    get("name"),
			Cmdline: get("commandline"),
			ExePath: get("executablepath"),
		})
	}
	return processes, nil
}

// collectViaCIM uses PowerShell Get-CimInstance as a fallback for systems
// where WMIC has been removed (Windows 11 22H2+).
func collectViaCIM(agentID int) []models.Process {

	script := `
Get-CimInstance Win32_Process |
  Select-Object ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath |
  ConvertTo-Json -Compress
`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		fmt.Println("[collector] processes: CIM fallback failed:", err)
		return nil
	}

	// PowerShell returns either a JSON array or a single object.
	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return nil
	}

	type cimProc struct {
		PID     int    `json:"ProcessId"`
		PPID    int    `json:"ParentProcessId"`
		Name    string `json:"Name"`
		Cmdline string `json:"CommandLine"`
		ExePath string `json:"ExecutablePath"`
	}

	// Normalise to array.
	var items []cimProc
	if strings.HasPrefix(raw, "[") {
		json.Unmarshal([]byte(raw), &items)
	} else {
		var single cimProc
		if err := json.Unmarshal([]byte(raw), &single); err == nil {
			items = []cimProc{single}
		}
	}

	processes := make([]models.Process, 0, len(items))
	for _, item := range items {
		processes = append(processes, models.Process{
			AgentID: agentID,
			PID:     item.PID,
			PPID:    item.PPID,
			Name:    item.Name,
			Cmdline: item.Cmdline,
			ExePath: item.ExePath,
		})
	}
	return processes
}

// splitCSV splits a comma-separated line, handling quoted fields.
func splitCSV(line string) []string {
	var fields []string
	var cur strings.Builder
	inQuote := false
	for _, ch := range line {
		switch {
		case ch == '"':
			inQuote = !inQuote
		case ch == ',' && !inQuote:
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(ch)
		}
	}
	fields = append(fields, cur.String())
	return fields
}

// atoiSafe converts a string to int, returning 0 on error.
func atoiSafe(s string) int {
	n := 0
	fmt.Sscanf(s, "%d", &n)
	return n
}
