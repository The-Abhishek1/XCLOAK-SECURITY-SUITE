package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"xcloak-agent/models"
)

type RestorePayload struct {
	QuarantinePath string `json:"quarantine_path"`
	RestorePath    string `json:"restore_path"`
}

// RestoreQuarantinedFile moves a quarantined file back to its original path.
// Dispatched by the backend when an analyst releases a quarantine record.
func RestoreQuarantinedFile(task models.AgentTask) string {
	var payload RestorePayload
	if err := json.Unmarshal(task.Payload, &payload); err != nil {
		return "restore_file: invalid payload: " + err.Error()
	}

	if payload.QuarantinePath == "" || payload.RestorePath == "" {
		return "restore_file: missing quarantine_path or restore_path"
	}

	// Ensure source exists.
	if _, err := os.Stat(payload.QuarantinePath); err != nil {
		return fmt.Sprintf("restore_file: source not found: %s", payload.QuarantinePath)
	}

	// Ensure destination directory exists.
	destDir := filepath.Dir(payload.RestorePath)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Sprintf("restore_file: cannot create dest dir %s: %v", destDir, err)
	}

	// Move file.
	if err := os.Rename(payload.QuarantinePath, payload.RestorePath); err != nil {
		// Fallback: copy then delete.
		if copyErr := copyFile(payload.QuarantinePath, payload.RestorePath); copyErr != nil {
			return fmt.Sprintf("restore_file: move and copy both failed: %v / %v", err, copyErr)
		}
		os.Remove(payload.QuarantinePath)
	}

	return fmt.Sprintf("restored: %s → %s", payload.QuarantinePath, payload.RestorePath)
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}
