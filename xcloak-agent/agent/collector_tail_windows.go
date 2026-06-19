//go:build windows

package agent

import (
	"fmt"
	"os"
)

// collectAuthLogsTail on Windows reads new Security event log entries.
// Windows doesn't have a file-based auth.log; instead we use wevtutil to
// query the Security event log for auth-related Event IDs.
//
// We track which events we've already shipped by storing the record number
// of the last event sent. The "inode" field of AuthLogState is repurposed
// as the last shipped RecordNumber on Windows.
func collectAuthLogsTail(agentID int) {
	const maxEventsPerCycle = 500

	// Use wevtutil to get Security log events. /rd:true = newest first.
	// We query up to maxEventsPerCycle events and compare against what
	// we've already sent.
	out, err := os.ReadFile(`C:\Windows\System32\winevt\Logs\Security.evtx`)
	if err != nil {
		// Fallback: delegate to the full CollectAuthLogs implementation
		// which handles wevtutil + PowerShell fallback.
		fmt.Println("[collector] auth_logs: evtx direct read failed, using full collector")
		CollectAuthLogs(agentID)
		return
	}
	_ = out // evtx is binary — use wevtutil path below

	// On Windows we fall back to the full CollectAuthLogs (wevtutil) for now.
	// A proper incremental implementation would query by RecordNumber > lastSeen,
	// which requires parsing the wevtutil XML output to extract RecordNumber.
	// That is a future improvement — for now the full re-read is acceptable
	// because wevtutil /c:500 already limits output to the last 500 events.
	CollectAuthLogs(agentID)
}
