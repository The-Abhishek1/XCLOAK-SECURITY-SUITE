package agent

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"os"

	"xcloak-agent/config"
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

	http.Post(
		config.ServerURL+"/api/agents/logs",
		"application/json",
		bytes.NewBuffer(body),
	)

	println(
		"Auth logs sent:",
		len(logs),
	)
}
