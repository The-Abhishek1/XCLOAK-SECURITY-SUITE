//go:build !windows

package agent

import (
	"fmt"
	"os"
)

// collectAuthLogsTail reads only NEW lines from /var/log/auth.log (or
// /var/log/secure on RHEL/Fedora) since the last successful collection.
//
// How it works:
//  1. Open the log file and stat its inode.
//  2. If the inode changed vs last run → file was rotated; reset offset to 0.
//  3. Seek to the stored byte offset.
//  4. Read new lines up to maxLinesPerCycle.
//  5. Ship them to the server; only advance the stored offset on success.
//
// This means: on a 2-minute cycle with a busy system emitting 50 log lines/min,
// we ship ~100 lines per cycle instead of re-sending the whole file (which
// could be 50,000+ lines on a long-lived system).
func collectAuthLogsTail(agentID int) {
	const maxLinesPerCycle = 2000

	// Try auth.log (Debian/Ubuntu) first, fall back to secure (RHEL/Fedora/CentOS).
	logPath := "/var/log/auth.log"
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		logPath = "/var/log/secure"
	}

	f, err := os.Open(logPath)
	if err != nil {
		// Neither file exists — nothing to collect.
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return
	}

	// ── Rotation detection ──────────────────────────────────────
	AuthLogState.mu.Lock()
	currentInode := fileInode(fi)
	if currentInode != AuthLogState.inode {
		if AuthLogState.inode != 0 {
			fmt.Printf("[collector] auth_logs: rotation detected (inode %d → %d), resetting offset\n",
				AuthLogState.inode, currentInode)
		}
		AuthLogState.offset = 0
		AuthLogState.inode = currentInode
	}
	seekOffset := AuthLogState.offset
	AuthLogState.mu.Unlock()

	// ── Handle file shrink (logrotate copytruncate) ─────────────
	fileSize := fi.Size()
	if seekOffset > fileSize {
		fmt.Printf("[collector] auth_logs: file shrank (%d → %d bytes), resetting offset\n",
			seekOffset, fileSize)
		AuthLogState.mu.Lock()
		AuthLogState.offset = 0
		AuthLogState.mu.Unlock()
		seekOffset = 0
	}

	// ── Seek to last read position ──────────────────────────────
	if seekOffset > 0 {
		if _, err := f.Seek(seekOffset, 0); err != nil {
			f.Seek(0, 0)
			seekOffset = 0
		}
	}

	// ── Read new lines ──────────────────────────────────────────
	newLines, bytesRead := readNewLines(f, maxLinesPerCycle)
	if len(newLines) == 0 {
		return
	}

	// ── Ship to server ──────────────────────────────────────────
	source := "auth.log"
	if logPath == "/var/log/secure" {
		source = "secure"
	}

	if err := sendLogLines(agentID, source, newLines); err != nil {
		fmt.Printf("[collector] auth_logs: send failed: %v (will retry next cycle)\n", err)
		// Do NOT advance offset so we retry the same lines next cycle.
		return
	}

	// ── Advance stored offset ───────────────────────────────────
	AuthLogState.mu.Lock()
	AuthLogState.offset = seekOffset + bytesRead
	AuthLogState.mu.Unlock()

	fmt.Printf("[collector] auth_logs: sent %d new lines (%d bytes)\n", len(newLines), bytesRead)
}
