//go:build linux

package agent

import (
	"fmt"
	"os"
	"syscall"
)

// replaceAndRestart overwrites the currently-running executable with the
// verified new binary and re-execs into it — same PID, no external process
// supervisor required (this codebase has none on any platform; see the
// agent survey this feature was scoped from). Safe on Linux specifically
// because the kernel only cares about the inode backing the running
// process's text segment — replacing the file at that path doesn't disturb
// the process currently executing the old inode's contents, so the
// rename can happen while still running, followed by exec into the new path.
func replaceAndRestart(newBinaryPath, newVersion string) error {
	currentPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve current executable path: %w", err)
	}

	backupPath := currentPath + ".bak"
	if err := copyExecutableFile(currentPath, backupPath); err != nil {
		fmt.Printf("[self-update] warning: could not save backup at %s: %v\n", backupPath, err)
	}

	if err := os.Rename(newBinaryPath, currentPath); err != nil {
		return fmt.Errorf("replace binary at %s: %w", currentPath, err)
	}

	fmt.Printf("[self-update] binary replaced with v%s — re-executing in place\n", newVersion)
	return syscall.Exec(currentPath, os.Args, os.Environ())
}
