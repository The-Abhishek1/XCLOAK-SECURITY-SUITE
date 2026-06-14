//go:build windows

package agent

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"xcloak-agent/models"
)

// CollectServices on Windows uses sc query to list services.
func CollectServices(agentID int) {

	out, err := exec.Command("sc", "query", "type=", "all", "state=", "all").Output()
	if err != nil {
		fmt.Println("CollectServices: sc query failed:", err)
		return
	}

	var services []models.Service

	var currentName, currentState string

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "SERVICE_NAME:") {
			currentName = strings.TrimSpace(strings.TrimPrefix(line, "SERVICE_NAME:"))
		} else if strings.HasPrefix(line, "STATE") && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				stateParts := strings.Fields(strings.TrimSpace(parts[1]))
				if len(stateParts) >= 2 {
					currentState = stateParts[1] // RUNNING, STOPPED, etc.
				}
			}

			if currentName != "" {
				services = append(services, models.Service{
					AgentID:     agentID,
					ServiceName: currentName,
					Status:      strings.ToLower(currentState),
				})
				currentName  = ""
				currentState = ""
			}
		}
	}

	body, _ := json.Marshal(services)
	resp, err := authPost("/api/agents/services", body)
	if err != nil {
		fmt.Println("CollectServices: send failed:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Services sent: %d\n", len(services))
}
