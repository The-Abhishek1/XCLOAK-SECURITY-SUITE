package agent

import (
	"bufio"
	"encoding/json"
	"os/exec"
	"strings"

	"xcloak-agent/models"
)

func CollectConnections(agentID int) {

	cmd := exec.Command(
		"ss",
		"-tun",
	)

	output, err := cmd.Output()

	if err != nil {
		println("Connection collection failed")
		return
	}

	var connections []models.Connection

	scanner := bufio.NewScanner(
		strings.NewReader(
			string(output),
		),
	)

	first := true

	for scanner.Scan() {

		if first {
			first = false
			continue
		}

		fields := strings.Fields(
			scanner.Text(),
		)

		if len(fields) < 6 {
			continue
		}

		connection := models.Connection{
			AgentID:       agentID,
			Protocol:      fields[0],
			State:         fields[1],
			LocalAddress:  fields[4],
			RemoteAddress: fields[5],
		}

		connections = append(
			connections,
			connection,
		)
	}

	body, _ := json.Marshal(
		connections,
	)

	resp, err := authPost("/api/agents/connections", body)

	if err != nil {
		println("Failed sending connections")
		return
	}

	defer resp.Body.Close()

	println(
		"Connections sent:",
		len(connections),
	)
}
