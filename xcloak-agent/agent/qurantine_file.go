//go:build !windows

package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"xcloak-agent/models"
)

type QuarantineFilePayload struct {
	Path string `json:"path"`
}

func QuarantineFile(
	task models.AgentTask,
) error {

	var payload QuarantineFilePayload

	err := json.Unmarshal(
		task.Payload,
		&payload,
	)

	if err != nil {
		return err
	}

	err = os.MkdirAll(
		"/tmp/xcloak-quarantine",
		0755,
	)

	if err != nil {
		return err
	}

	fileName := filepath.Base(
		payload.Path,
	)

	newPath := filepath.Join(
		"/tmp/xcloak-quarantine",
		fileName,
	)

	err = os.Rename(
		payload.Path,
		newPath,
	)

	if err != nil {
		return err
	}

	fmt.Println(
		"Quarantined:",
		payload.Path,
	)

	return nil
}
