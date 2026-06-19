//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"xcloak-agent/models"
)

const scriptTimeout = 120 * time.Second

// ExecuteScript on Windows supports PowerShell, cmd, and python3.
// PowerShell is the primary shell — use it for any Windows-specific tasks
// (registry queries, WMI, event log queries, etc.).
func ExecuteScript(task models.AgentTask) (string, error) {

	var payload ExecuteScriptPayload
	if err := json.Unmarshal(task.Payload, &payload); err != nil {
		return "", fmt.Errorf("invalid payload: %w", err)
	}

	shell := payload.Shell
	if shell == "" {
		shell = "powershell"
	}

	allowed := map[string]bool{
		"powershell": true,
		"cmd":        true,
		"python3":    true,
		"python":     true,
	}
	if !allowed[shell] {
		return "", fmt.Errorf("shell %q not permitted (allowed: powershell, cmd, python3)", shell)
	}

	ctx, cancel := context.WithTimeout(context.Background(), scriptTimeout)
	defer cancel()

	var cmd *exec.Cmd

	switch shell {
	case "powershell":
		// -NoProfile    : skip user profile (faster, no side effects)
		// -NonInteractive: no prompts
		// -Command      : run script string
		cmd = exec.CommandContext(ctx,
			"powershell", "-NoProfile", "-NonInteractive",
			"-ExecutionPolicy", "Bypass",
			"-Command", payload.Script,
		)
	case "cmd":
		cmd = exec.CommandContext(ctx, "cmd", "/C", payload.Script)
	default:
		// python3 / python — same as Linux
		cmd = exec.CommandContext(ctx, shell, "-c", payload.Script)
	}

	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return string(output) + "\n[TIMEOUT after 120s]", fmt.Errorf("script timed out")
	}

	if err != nil {
		return string(output), fmt.Errorf("exit %w", err)
	}

	return string(output), nil
}
