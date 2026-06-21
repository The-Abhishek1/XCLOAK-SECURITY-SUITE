//go:build !windows

package agent

import "syscall"

// processAlive sends signal 0, which performs no action but still reports
// ESRCH if the PID no longer exists — the standard way to check liveness
// without actually signaling the process.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}
