//go:build windows

package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"xcloak-agent-desktop/models"
)

// QuarantineFile on Windows moves the target file into
// %ProgramData%\XCloak\Quarantine\ and locks it with icacls so only
// SYSTEM can access it, preventing the malware from running again.
func QuarantineFile(task models.AgentTask) error {

	var payload QuarantineFilePayload
	if err := json.Unmarshal(task.Payload, &payload); err != nil {
		return err
	}
	if payload.Path == "" {
		return fmt.Errorf("quarantine_file: empty path")
	}

	// ── Choose quarantine directory ───────────────────────────────
	// Prefer %ProgramData%\XCloak\Quarantine; fall back to TEMP.
	qDir := filepath.Join(os.Getenv("PROGRAMDATA"), "XCloak", "Quarantine")
	if os.Getenv("PROGRAMDATA") == "" {
		qDir = filepath.Join(os.TempDir(), "XCloak-Quarantine")
	}
	if err := os.MkdirAll(qDir, 0700); err != nil {
		return fmt.Errorf("quarantine_file: cannot create dir %s: %w", qDir, err)
	}

	fileName := filepath.Base(payload.Path)
	destPath  := filepath.Join(qDir, fileName)

	// ── Move the file ─────────────────────────────────────────────
	if err := os.Rename(payload.Path, destPath); err != nil {
		// Rename fails across drives — copy then delete.
		if copyErr := copyFile(payload.Path, destPath); copyErr != nil {
			return fmt.Errorf("quarantine_file: move (%v) and copy (%v) both failed", err, copyErr)
		}
		os.Remove(payload.Path)
	}

	// ── Lock down ACLs via icacls ─────────────────────────────────
	// /inheritance:r  removes inherited ACEs
	// /grant:r        replaces (not adds) grants
	// SYSTEM:(F)      SYSTEM full control only
	out, err := exec.Command("icacls", destPath,
		"/inheritance:r",
		"/grant:r", `SYSTEM:(F)`,
	).CombinedOutput()
	if err != nil {
		fmt.Printf("[quarantine] ACL lock partial: %s\n", string(out))
	}

	fmt.Printf("[quarantine] %s → %s\n", payload.Path, destPath)
	return nil
}
