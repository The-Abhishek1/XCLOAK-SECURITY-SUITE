package agent

import (
	"encoding/json"
	"os/exec"

	"xcloak-agent/models"
)

type ExecuteScriptPayload struct {
	Script string `json:"script"`
}

func ExecuteScript(
	task models.AgentTask,
) (string, error) {

	var payload ExecuteScriptPayload

	err := json.Unmarshal(
		task.Payload,
		&payload,
	)

	if err != nil {
		return "", err
	}

	cmd := exec.Command(
		"bash",
		"-c",
		payload.Script,
	)

	output, err := cmd.CombinedOutput()

	if err != nil {
		return string(output), err
	}

	return string(output), nil
}
