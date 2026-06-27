//go:build !linux

package agent

import "fmt"

// replaceAndRestart on Windows/macOS: there's no process supervisor
// anywhere in this codebase to coordinate swapping a locked, currently
// running executable, and overwriting it directly isn't possible while
// it's running (unlike Linux, where replacing the underlying inode is
// safe). The verified, checksum-matched binary is left at newBinaryPath
// for an operator to apply on next restart rather than risking a half
// -applied update with nothing to bring the agent back if it goes wrong.
func replaceAndRestart(newBinaryPath, newVersion string) error {
	fmt.Printf("[self-update] downloaded and verified v%s to %s — restart the agent manually to apply (no in-place replace on this platform)\n", newVersion, newBinaryPath)
	return nil
}
