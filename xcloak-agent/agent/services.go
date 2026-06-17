//go:build !windows

package agent

import (
	"bufio"
	"encoding/json"
	"os/exec"
	"strings"

	"xcloak-agent/models"
)

func CollectServices(agentID int) {

	cmd := exec.Command(
		"systemctl",
		"list-units",
		"--type=service",
		"--no-pager",
		"--no-legend",
	)

	output, err := cmd.Output()

	if err != nil {
		println("Service collection failed")
		return
	}

	var services []models.Service

	scanner := bufio.NewScanner(
		strings.NewReader(
			string(output),
		),
	)

	for scanner.Scan() {

		fields := strings.Fields(
			scanner.Text(),
		)

		if len(fields) < 4 {
			continue
		}

		service := models.Service{
			AgentID:      agentID,
			ServiceName:  fields[0],
			ServiceState: fields[2],
		}

		services = append(
			services,
			service,
		)
	}

	body, _ := json.Marshal(
		services,
	)

	resp, err := authPost("/api/agents/services", body)

	if err != nil {
		println("Failed sending services")
		return
	}

	defer resp.Body.Close()

	println(
		"Services sent:",
		len(services),
	)
}
