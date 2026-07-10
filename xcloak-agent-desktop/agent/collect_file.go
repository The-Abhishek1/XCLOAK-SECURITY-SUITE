package agent

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"

	"xcloak-agent-desktop/models"
)

type CollectFilePayload struct {
	Path string `json:"path"`
}

func CollectFile(
	task models.AgentTask,
) {

	var payload CollectFilePayload

	err := json.Unmarshal(
		task.Payload,
		&payload,
	)

	if err != nil {
		return
	}

	data, err := os.ReadFile(
		payload.Path,
	)

	if err != nil {
		return
	}

	upload := models.FileUpload{
		AgentID:      task.AgentID,
		OriginalPath: payload.Path,
		FileName:     filepath.Base(payload.Path),
		Content:      base64.StdEncoding.EncodeToString(data),
	}

	body, _ := json.Marshal(upload)

	resp, err := authPost("/api/agents/file", body)

	if err != nil {
		println("Failed sending collected file")
		return
	}

	defer resp.Body.Close()

	println(
		"Collected:",
		payload.Path,
	)
}
