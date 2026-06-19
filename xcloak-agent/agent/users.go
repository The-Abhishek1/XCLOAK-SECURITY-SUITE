//go:build !windows

package agent

import (
	"bufio"
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"xcloak-agent/models"
)

func CollectUsers(agentID int) {

	file, err := os.Open("/etc/passwd")

	if err != nil {
		println("Failed to read passwd")
		return
	}

	defer file.Close()

	var users []models.User

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {

		line := scanner.Text()

		fields := strings.Split(
			line,
			":",
		)

		if len(fields) < 7 {
			continue
		}

		uid, _ := strconv.Atoi(
			fields[2],
		)

		user := models.User{
			AgentID:  agentID,
			Username: fields[0],
			UID:      uid,
			Shell:    fields[6],
		}

		users = append(
			users,
			user,
		)
	}

	body, _ := json.Marshal(users)

	resp, err := authPost("/api/agents/users", body)

	if err != nil {
		println("Failed sending users")
		return
	}

	defer resp.Body.Close()

	println(
		"Users sent:",
		len(users),
	)
}
