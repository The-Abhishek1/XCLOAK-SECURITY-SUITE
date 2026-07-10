//go:build windows

package agent

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"xcloak-agent-desktop/models"
)

// CollectAuthLogs on Windows queries the Security event log for logon events.
// Event IDs:
//   4624 = Successful logon
//   4625 = Failed logon
//   4648 = Logon with explicit credentials
//   4634 = Logoff
func CollectAuthLogs(agentID int) {

	// Use wevtutil to query Security log for last 500 auth events.
	out, err := exec.Command("wevtutil", "qe", "Security",
		"/q:*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4634)]]",
		"/c:500", "/rd:true", "/f:Text",
	).Output()

	if err != nil {
		fmt.Println("CollectAuthLogs: wevtutil failed:", err)
		// Fallback: try PowerShell Get-EventLog
		collectAuthLogsPS(agentID)
		return
	}

	var logs []models.Log
	var currentLog strings.Builder

	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" && currentLog.Len() > 0 {
			entry := strings.TrimSpace(currentLog.String())
			if entry != "" {
				logs = append(logs, models.Log{
					AgentID:    agentID,
					LogSource:  "Security",
					LogMessage: entry[:min(len(entry), 500)],
				})
			}
			currentLog.Reset()
		} else {
			currentLog.WriteString(line)
			currentLog.WriteString(" ")
		}

		if len(logs) >= 500 {
			break
		}
	}

	if len(logs) == 0 {
		fmt.Println("CollectAuthLogs: no auth events found")
		return
	}

	body, _ := json.Marshal(logs)
	resp, err := authPost("/api/agents/logs", body)
	if err != nil {
		fmt.Println("CollectAuthLogs: send failed:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Auth logs sent: %d\n", len(logs))
}

// collectAuthLogsPS is a PowerShell fallback.
func collectAuthLogsPS(agentID int) {

	out, err := exec.Command("powershell", "-Command",
		`Get-EventLog -LogName Security -InstanceId 4624,4625 -Newest 200 | `+
			`Select-Object -ExpandProperty Message`,
	).Output()

	if err != nil {
		fmt.Println("CollectAuthLogs PS fallback failed:", err)
		return
	}

	var logs []models.Log
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		logs = append(logs, models.Log{
			AgentID:    agentID,
			LogSource:  "Security-PS",
			LogMessage: line,
		})
		if len(logs) >= 200 {
			break
		}
	}

	body, _ := json.Marshal(logs)
	resp, _ := authPost("/api/agents/logs", body)
	if resp != nil {
		resp.Body.Close()
	}
}

