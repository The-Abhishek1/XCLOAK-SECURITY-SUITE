package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"

	"net/http"

	"xcloak-agent/config"
	"xcloak-agent/models"
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

	http.Post(
		config.ServerURL+"/api/agents/file",
		"application/json",
		bytes.NewBuffer(body),
	)

	println(
		"Collected:",
		payload.Path,
	)
}
