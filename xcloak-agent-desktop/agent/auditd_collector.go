//go:build !windows

package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// AuditEvent represents a single execve event reconstructed from auditd logs.
//
// auditd writes execve events across two lines:
//   type=SYSCALL: pid, ppid, uid, euid, comm, exe, success
//   type=EXECVE:  argc, a0, a1, a2… (the full argument vector)
//
// We join them by audit event ID (the number in the msg= field) so we can
// reconstruct the full command line from the split EXECVE fields.
// ─────────────────────────────────────────────────────────────────────────────

type AuditEvent struct {
	AgentID   int    `json:"agent_id"`
	EventID   string `json:"event_id"`    // audit event sequence number
	Timestamp string `json:"timestamp"`   // e.g. "1718000000.123"
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid"`
	UID       int    `json:"uid"`
	EUID      int    `json:"euid"`
	Username  string `json:"username"`    // resolved from UID if available
	Comm      string `json:"comm"`        // truncated name (from SYSCALL)
	Exe       string `json:"exe"`         // full binary path (from SYSCALL)
	Cmdline   string `json:"cmdline"`     // full argv joined (from EXECVE)
	Success   string `json:"success"`     // "yes" | "no"
	// Detection fields added server-side:
	ThreatTag string `json:"threat_tag,omitempty"` // e.g. "reverse_shell"
}

// ─────────────────────────────────────────────────────────────────────────────
// Tail state for audit.log — same offset-tracking approach as auth logs.
// ─────────────────────────────────────────────────────────────────────────────

var auditLogState = &LogTailState{}

// ─────────────────────────────────────────────────────────────────────────────
// CollectAuditEvents reads new execve records from /var/log/audit/audit.log,
// parses them into AuditEvent structs, and ships them to the server.
//
// Called by StartCollectors every 30 seconds for near-real-time command
// visibility. On busy systems this yields:
//   • Every command run by any user, including root
//   • Full argv — catches "python3 -c exec(base64decode(...))"
//   • Parent PID — shows if bash spawned from sshd, cron, python, etc.
//   • UID + EUID — catches privilege escalation (uid=1000, euid=0)
// ─────────────────────────────────────────────────────────────────────────────

func CollectAuditEvents(agentID int) {
	const auditLog = "/var/log/audit/audit.log"
	const maxEventsPerCycle = 500

	f, err := os.Open(auditLog)
	if err != nil {
		// auditd not installed or insufficient permissions.
		// Non-fatal — fallback to /proc cmdline enrichment in CollectProcesses.
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return
	}

	// ── Rotation detection ──────────────────────────────────────
	auditLogState.mu.Lock()
	currentInode := fileInode(fi)
	if currentInode != auditLogState.inode {
		auditLogState.offset = 0
		auditLogState.inode = currentInode
	}
	seekOffset := auditLogState.offset

	// Handle file shrink (logrotate).
	if seekOffset > fi.Size() {
		seekOffset = 0
		auditLogState.offset = 0
	}
	auditLogState.mu.Unlock()

	if seekOffset > 0 {
		if _, err := f.Seek(seekOffset, 0); err != nil {
			f.Seek(0, 0)
			seekOffset = 0
		}
	}

	// ── Read and parse new lines ─────────────────────────────────
	lines, bytesRead := readNewLines(f, maxEventsPerCycle*5) // ~5 lines per event
	if len(lines) == 0 {
		return
	}

	events := parseAuditLines(agentID, lines)
	if len(events) == 0 {
		auditLogState.mu.Lock()
		auditLogState.offset = seekOffset + bytesRead
		auditLogState.mu.Unlock()
		return
	}

	// ── Ship to server ──────────────────────────────────────────
	body, _ := json.Marshal(events)
	resp, err := authPost("/api/agents/audit-events", body)
	if err != nil {
		fmt.Printf("[collector] auditd: send failed: %v\n", err)
		return // don't advance offset — retry same lines next cycle
	}
	defer resp.Body.Close()

	// ── Advance offset ──────────────────────────────────────────
	auditLogState.mu.Lock()
	auditLogState.offset = seekOffset + bytesRead
	auditLogState.mu.Unlock()

	fmt.Printf("[collector] auditd: sent %d events\n", len(events))
}

// ─────────────────────────────────────────────────────────────────────────────
// parseAuditLines converts raw auditd log lines into complete AuditEvents.
//
// auditd groups a single execve event across multiple lines sharing the same
// event ID. The pattern is:
//
//   type=SYSCALL msg=audit(1718000000.123:4567): arch=... syscall=59 ...
//     pid=1234 ppid=5678 uid=0 euid=0 ... comm="bash" exe="/bin/bash" ...
//   type=EXECVE msg=audit(1718000000.123:4567): argc=3 a0="bash" a1="-c" a2="whoami"
//
// We accumulate partial events by ID in a map, then emit complete ones
// (those with both SYSCALL + EXECVE seen) to keep only execve events.
// ─────────────────────────────────────────────────────────────────────────────

func parseAuditLines(agentID int, lines []string) []AuditEvent {

	// partial holds events being assembled; flushed at end.
	type partial struct {
		syscall *AuditEvent
		argv    []string // collected from a0, a1, a2…
		argc    int
	}
	pm := make(map[string]*partial)
	var mu sync.Mutex

	flush := func(id string) *AuditEvent {
		mu.Lock()
		defer mu.Unlock()
		p, ok := pm[id]
		if !ok || p.syscall == nil {
			return nil
		}
		if len(p.argv) > 0 {
			p.syscall.Cmdline = strings.Join(p.argv, " ")
		}
		ev := p.syscall
		delete(pm, id)
		return ev
	}

	var completed []AuditEvent

	for _, line := range lines {
		// Only care about execve-related record types.
		recType := extractField(line, "type=", " ")
		if recType != "SYSCALL" && recType != "EXECVE" {
			continue
		}

		// Ignore SYSCALL lines that are NOT execve (syscall=59 on x86_64,
		// syscall=11 on arm, syscall=221 on arm64).
		if recType == "SYSCALL" {
			sc := extractField(line, " syscall=", " ")
			if sc != "59" && sc != "11" && sc != "221" {
				continue
			}
		}

		// Extract event ID from msg=audit(timestamp:id)
		msgField := extractField(line, "msg=audit(", ")")
		if msgField == "" {
			continue
		}
		parts := strings.SplitN(msgField, ":", 2)
		if len(parts) != 2 {
			continue
		}
		ts, id := parts[0], parts[1]

		mu.Lock()
		if _, ok := pm[id]; !ok {
			pm[id] = &partial{}
		}
		p := pm[id]
		mu.Unlock()

		switch recType {
		case "SYSCALL":
			ev := &AuditEvent{
				AgentID:   agentID,
				EventID:   id,
				Timestamp: ts,
				PID:       atoiField(line, " pid="),
				PPID:      atoiField(line, " ppid="),
				UID:       atoiField(line, " uid="),
				EUID:      atoiField(line, " euid="),
				Comm:      stripQuotes(extractField(line, " comm=", " ")),
				Exe:       stripQuotes(extractField(line, " exe=", " ")),
				Success:   extractField(line, " res=", " "),
			}
			// Resolve username from /etc/passwd (best-effort, cached).
			ev.Username = resolveUsername(ev.UID)
			mu.Lock()
			p.syscall = ev
			mu.Unlock()

		case "EXECVE":
			argc := atoiField(line, "argc=")
			mu.Lock()
			p.argc = argc
			mu.Unlock()

			// Collect a0, a1, a2… in order.
			args := make([]string, argc)
			for i := 0; i < argc; i++ {
				key := fmt.Sprintf(" a%d=", i)
				val := extractField(line, key, " ")
				if val == "" {
					// Some auditd versions use a0[0]= for long args — skip for now.
					break
				}
				args[i] = stripQuotes(val)
			}
			mu.Lock()
			p.argv = args
			mu.Unlock()

			// EXECVE always comes after SYSCALL for the same event,
			// so the event is complete as soon as we see EXECVE.
			if ev := flush(id); ev != nil {
				completed = append(completed, *ev)
			}
		}
	}

	// Flush any partially assembled events (e.g. SYSCALL without EXECVE yet).
	mu.Lock()
	for id := range pm {
		p := pm[id]
		if p.syscall != nil && p.syscall.Exe != "" {
			if len(p.argv) > 0 {
				p.syscall.Cmdline = strings.Join(p.argv, " ")
			} else {
				p.syscall.Cmdline = p.syscall.Comm
			}
			completed = append(completed, *p.syscall)
		}
	}
	mu.Unlock()

	return completed
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// extractField pulls the value after `prefix` up to `terminator` (or EOL).
// e.g. extractField(line, " exe=", " ") → "/bin/bash"
func extractField(line, prefix, terminator string) string {
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return ""
	}
	start := idx + len(prefix)
	rest := line[start:]
	if terminator == "" {
		return rest
	}
	end := strings.Index(rest, terminator)
	if end < 0 {
		return rest
	}
	return rest[:end]
}

// atoiField extracts an integer value after prefix.
func atoiField(line, prefix string) int {
	val := extractField(line, prefix, " ")
	n, _ := strconv.Atoi(val)
	return n
}

// stripQuotes removes surrounding double-quotes if present.
func stripQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// ─────────────────────────────────────────────────────────────────────────────
// Username cache — resolves UID → username from /etc/passwd.
// Avoids hammering the filesystem on every event.
// ─────────────────────────────────────────────────────────────────────────────

var (
	usernameCache   = make(map[int]string)
	usernameCacheMu sync.RWMutex
	passwdLoaded    bool
	passwdLoadedAt  time.Time
)

const usernameCacheTTL = 10 * time.Minute

func resolveUsername(uid int) string {
	usernameCacheMu.RLock()
	if name, ok := usernameCache[uid]; ok && time.Since(passwdLoadedAt) < usernameCacheTTL {
		usernameCacheMu.RUnlock()
		return name
	}
	usernameCacheMu.RUnlock()

	// Reload /etc/passwd.
	usernameCacheMu.Lock()
	defer usernameCacheMu.Unlock()

	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return ""
	}

	// Clear and rebuild.
	for k := range usernameCache {
		delete(usernameCache, k)
	}

	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		name := parts[0]
		id, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		usernameCache[id] = name
	}

	passwdLoadedAt = time.Now()
	return usernameCache[uid]
}
