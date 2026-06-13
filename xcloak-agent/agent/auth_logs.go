package agent

import (
	"bufio"
	"encoding/json"
	"os"

	"xcloak-agent/models"
)

func CollectAuthLogs(agentID int) {

	file, err := os.Open(
		"/var/log/auth.log",
	)

	if err != nil {
		println("auth.log not found")
		return
	}

	defer file.Close()

	var logs []models.Log

	scanner := bufio.NewScanner(file)

	count := 0

	for scanner.Scan() {

		logs = append(logs, models.Log{
			AgentID:    agentID,
			LogSource:  "auth.log",
			LogMessage: scanner.Text(),
		})

		count++

		if count >= 500 {
			break
		}
	}

	body, _ := json.Marshal(logs)

	resp, err := authPost("/api/agents/logs", body)

	if err != nil {
		println("Failed sending auth logs")
		return
	}

	defer resp.Body.Close()

	println(
		"Auth logs sent:",
		len(logs),
	)
}
