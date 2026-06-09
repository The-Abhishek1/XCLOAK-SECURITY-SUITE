package agent

import (
	"encoding/json"
	"os"
	"strconv"

	"xcloak-agent/models"
)

type KillProcessPayload struct {
	PID int `json:"pid"`
}

func KillProcess(
	task models.AgentTask,
) {

	var payload KillProcessPayload

	err := json.Unmarshal(
		task.Payload,
		&payload,
	)

	if err != nil {
		println("invalid payload")
		return
	}

	process, err := os.FindProcess(
		payload.PID,
	)

	if err != nil {
		println("process not found")
		return
	}

	err = process.Kill()

	if err != nil {
		println("failed to kill")
		return
	}

	println(
		"Killed PID:",
		strconv.Itoa(payload.PID),
	)
}
