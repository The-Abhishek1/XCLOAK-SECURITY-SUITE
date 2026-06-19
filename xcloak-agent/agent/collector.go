package agent

import (
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Collection intervals
// ─────────────────────────────────────────────────────────────────────────────

const (
	intervalProcesses   = 5 * time.Minute
	intervalConnections = 5 * time.Minute
	intervalServices    = 15 * time.Minute
	intervalUsers       = 30 * time.Minute
	intervalAuthLogs    = 2 * time.Minute // more frequent — feeds SIEM detections
	intervalPackages    = 6 * time.Hour   // slow-changing, expensive to collect
	intervalFileHashes  = 1 * time.Hour   // CPU-intensive directory walk
)

// maxJitter is added as a random delay before the first tick of each
// collector so they don't all fire at t=0 and saturate the server.
const maxJitter = 30 * time.Second

// ─────────────────────────────────────────────────────────────────────────────
// Log-tail state — persists byte offset between collection cycles so auth log
// collection only ships NEW lines instead of re-reading the whole file.
// ─────────────────────────────────────────────────────────────────────────────

// LogTailState tracks read position for a single tailed log file.
type LogTailState struct {
	mu     sync.Mutex
	offset int64
	inode  uint64 // 0 on Windows (no inode API)
}

// AuthLogState is the shared tail state for auth.log / /var/log/secure.
var AuthLogState = &LogTailState{}

// ─────────────────────────────────────────────────────────────────────────────
// StartCollectors launches all autonomous collection goroutines.
// Call once, immediately after the agent is registered.
// ─────────────────────────────────────────────────────────────────────────────

func StartCollectors(agentID int) {
	fmt.Printf("[collector] Starting autonomous collection for agent #%d\n", agentID)

	go runCollector("processes",   intervalProcesses,   maxJitter, func() { CollectProcesses(agentID) })
	go runCollector("connections", intervalConnections, maxJitter, func() { CollectConnections(agentID) })
	go runCollector("services",    intervalServices,    maxJitter, func() { CollectServices(agentID) })
	go runCollector("users",       intervalUsers,       maxJitter, func() { CollectUsers(agentID) })
	go runCollector("packages",    intervalPackages,    maxJitter, func() { CollectPackages(agentID) })

	// Auth logs use the incremental tail path — see collector_tail_linux.go /
	// collector_tail_windows.go for the platform-specific implementations.
	go runCollector("auth_logs", intervalAuthLogs, maxJitter, func() {
		collectAuthLogsTail(agentID)
	})

	// auditd execve events — near-real-time command-line monitoring.
	// No-op on Windows (stub in auditd_collector_windows.go).
	go runCollector("auditd", 30*time.Second, maxJitter, func() {
		CollectAuditEvents(agentID)
	})

	// Windows registry persistence keys — scanned hourly.
	// No-op on Linux (stub in registry_linux.go).
	go runCollector("registry", 1*time.Hour, maxJitter, func() {
		CollectRegistryPersistence(agentID)
	})

	// File hashes: the collector returns a slice; SendFileHashes ships it.
	go runCollector("file_hashes", intervalFileHashes, maxJitter, func() {
		hashes := CollectFileHashes(agentID)
		if len(hashes) > 0 {
			SendFileHashes(hashes)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// runCollector is the generic ticker loop shared by every collector.
//
//   - jitter: random delay before the first run so collectors start staggered.
//   - First run is immediate (no waiting a full interval after the jitter).
//   - Panics are caught, logged, and the goroutine is restarted after 60s.
// ─────────────────────────────────────────────────────────────────────────────

func runCollector(name string, interval, jitterMax time.Duration, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[collector] %s panicked: %v — restarting in 60s\n", name, r)
			time.Sleep(60 * time.Second)
			go runCollector(name, interval, jitterMax, fn)
		}
	}()

	jitter := time.Duration(rand.Int63n(int64(jitterMax)))
	fmt.Printf("[collector] %s: first run in %s, then every %s\n",
		name, jitter.Round(time.Second), interval)
	time.Sleep(jitter)

	// Run immediately after the jitter delay.
	runSafe(name, fn)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		runSafe(name, fn)
	}
}

// runSafe wraps a collector call in a recover so a single panicking collector
// does not bring down the agent process.
func runSafe(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[collector] %s: recovered from panic: %v\n", name, r)
		}
	}()
	fn()
}
