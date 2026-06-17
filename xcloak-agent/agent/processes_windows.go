//go:build windows

package agent

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"xcloak-agent/models"
)

// CollectProcesses on Windows uses tasklist /FO CSV to enumerate processes.
func CollectProcesses(agentID int) {

	out, err := exec.Command("tasklist", "/FO", "CSV", "/NH").Output()
	if err != nil {
		fmt.Println("CollectProcesses: tasklist failed:", err)
		return
	}

	var processes []models.Process

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// CSV format: "process.exe","PID","Session Name","Session#","Mem Usage"
		parts := strings.Split(line, "\",\"")
		if len(parts) < 2 {
			continue
		}

		name := strings.Trim(parts[0], "\"")
		pidStr := strings.Trim(parts[1], "\"")

		var pid int
		fmt.Sscanf(pidStr, "%d", &pid)

		processes = append(processes, models.Process{
			AgentID: agentID,
			PID:     pid,
			Name:    name,
		})
	}

	body, _ := json.Marshal(processes)

	resp, err := authPost("/api/agents/processes", body)
	if err != nil {
		fmt.Println("CollectProcesses: send failed:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Processes sent: %d\n", len(processes))
}
