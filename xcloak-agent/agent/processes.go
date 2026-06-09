package agent

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"os/exec"
	"strconv"
	"strings"

	"xcloak-agent/config"
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

	http.Post(
		config.ServerURL+"/api/agents/processes",
		"application/json",
		bytes.NewBuffer(body),
	)
}
