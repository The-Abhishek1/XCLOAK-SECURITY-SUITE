//go:build !windows

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"xcloak-agent/models"
)

type ExecuteScriptPayload struct {
	Script string `json:"script"`
	Shell  string `json:"shell"`  // "bash" | "sh" | "python3" — default bash
	Label  string `json:"label"`
}

const scriptTimeout = 120 * time.Second

func ExecuteScript(task models.AgentTask) (string, error) {
	var payload ExecuteScriptPayload
	if err := json.Unmarshal(task.Payload, &payload); err != nil {
		return "", fmt.Errorf("invalid payload: %w", err)
	}

	shell := payload.Shell
	if shell == "" {
		shell = "bash"
	}

	// Validate shell to prevent abuse.
	allowed := map[string]bool{"bash": true, "sh": true, "python3": true, "python": true}
	if !allowed[shell] {
		return "", fmt.Errorf("shell %q not permitted (allowed: bash, sh, python3)", shell)
	}

	ctx, cancel := context.WithTimeout(context.Background(), scriptTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, shell, "-c", payload.Script)

	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return string(output) + "\n[TIMEOUT after 120s]", fmt.Errorf("script timed out")
	}

	if err != nil {
		// Return output alongside the error — partial output is still useful.
		return string(output), fmt.Errorf("exit %w", err)
	}

	return string(output), nil
}
