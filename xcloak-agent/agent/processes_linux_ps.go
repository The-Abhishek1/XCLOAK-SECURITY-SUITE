//go:build !windows

package agent

import "os/exec"

// buildPSCommand returns the ps invocation for Linux/macOS.
// Format columns: pid ppid user %cpu %mem comm
// -ww prevents line truncation on some ps flavours.
func buildPSCommand() *exec.Cmd {
	return exec.Command(
		"ps",
		"-e",
		"-o", "pid,ppid,user,pcpu,pmem,comm",
		"--no-headers",
	)
}
