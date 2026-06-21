//go:build windows

package agent

import "golang.org/x/sys/windows"

const stillActive = 259 // STILL_ACTIVE exit code

// processAlive opens the process and checks its exit code — TerminateProcess
// is asynchronous, so right after Kill() the process may briefly still show
// as alive while Windows tears it down; callers should allow for that.
func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)

	var exitCode uint32
	if err := windows.GetExitCodeProcess(h, &exitCode); err != nil {
		return false
	}
	return exitCode == stillActive
}
