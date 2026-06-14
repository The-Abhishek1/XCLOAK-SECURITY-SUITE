//go:build windows

package agent

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"xcloak-agent/models"
)

// CollectConnections on Windows uses netstat -ano to list active connections.
func CollectConnections(agentID int) {

	out, err := exec.Command("netstat", "-ano").Output()
	if err != nil {
		fmt.Println("CollectConnections: netstat failed:", err)
		return
	}

	var connections []models.Connection

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Proto") || strings.HasPrefix(line, "Active") {
			continue
		}

		// Format: Proto  Local Address      Foreign Address    State   PID
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		proto := fields[0]
		local := fields[1]
		remote := fields[2]
		state  := ""

		if len(fields) >= 5 {
			state = fields[3]
		} else {
			// UDP has no state
			state = "LISTEN"
		}

		connections = append(connections, models.Connection{
			AgentID:       agentID,
			Protocol:      proto,
			LocalAddress:  local,
			RemoteAddress: remote,
			State:         state,
		})
	}

	body, _ := json.Marshal(connections)

	resp, err := authPost("/api/agents/connections", body)
	if err != nil {
		fmt.Println("CollectConnections: send failed:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Connections sent: %d\n", len(connections))
}
