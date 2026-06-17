//go:build !windows

package agent

import (
	"bufio"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"

	"xcloak-agent/models"
)

func CollectProcesses(agentID int) {

	cmd := exec.Command(
		"ps",
		"-eo",
		"pid,comm",
	)

	output, err := cmd.Output()

	if err != nil {
		return
	}

	var processes []models.Process

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

		if len(fields) < 2 {
			continue
		}

		pid, _ := strconv.Atoi(
			fields[0],
		)

		processes = append(
			processes,
			models.Process{
				AgentID: agentID,
				PID:     pid,
				Name:    fields[1],
			},
		)
	}

	body, _ := json.Marshal(
		processes,
	)

	resp, err := authPost("/api/agents/processes", body)

	if err != nil {
		println("Failed sending processes")
		return
	}

	defer resp.Body.Close()

	println(
		"Processes sent:",
		len(processes),
	)
}
