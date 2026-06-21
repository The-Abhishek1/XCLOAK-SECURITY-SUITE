package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"xcloak-agent/models"
)

type KillProcessPayload struct {
	PID int `json:"pid"`
}

// KillProcess sends the kill signal and then actually verifies the process
// died before reporting success — os.FindProcess never errors on a missing
// PID on Linux, and Kill() can return nil even when the PID was already
// gone or got reused, so without the recheck below the server would
// believe every kill_process task succeeded regardless of reality.
func KillProcess(task models.AgentTask) error {

	var payload KillProcessPayload
	if err := json.Unmarshal(task.Payload, &payload); err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}

	if !processAlive(payload.PID) {
		return fmt.Errorf("pid %d does not exist", payload.PID)
	}

	process, err := os.FindProcess(payload.PID)
	if err != nil {
		return fmt.Errorf("could not open pid %d: %w", payload.PID, err)
	}

	if err := process.Kill(); err != nil {
		return fmt.Errorf("failed to kill pid %d: %w", payload.PID, err)
	}

	// Termination is asynchronous on both platforms — give it a moment
	// before declaring victory.
	for i := 0; i < 10; i++ {
		if !processAlive(payload.PID) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("pid %d still alive 1s after kill", payload.PID)
}
