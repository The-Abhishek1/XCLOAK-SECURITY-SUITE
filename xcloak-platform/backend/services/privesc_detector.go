package services

// Privilege Escalation Detector
//
// Detects escalation of privileges on both Windows and Linux systems using
// parsed Windows Event IDs and Linux syslog patterns.
//
// Windows patterns (via EventID in parsed_fields):
//   4728 / 4732 / 4756  — member added to a privileged security group
//   4720               — new local user account created
//   4672               — special privileges (SeDebugPrivilege, etc.) assigned at logon
//   4798               — user's local group membership enumerated (recon signal)
//
// Linux patterns (via raw log_message text):
//   sudo ... COMMAND=  — successful sudo execution (any command)
//   su to root         — switched to root account
//   chmod [+]s / u+s   — SUID/SGID bit set (persistent privilege)
//   /etc/sudoers       — sudoers policy modification
//   /etc/passwd        — passwd database write (new user or pw change)
//
// Runs every 5 minutes. Alert dedup TTL: 15 minutes per (agentID, pattern, subject).

import (
	"fmt"
	"log"
	"strings"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

const privescDedupTTL = 15 * time.Minute

var privescDedup = newTTLMap(privescDedupTTL)

func StartPrivEscScheduler() {
	go func() {
		time.Sleep(3 * time.Minute)
		for {
			runPrivEscDetection()
			time.Sleep(5 * time.Minute)
		}
	}()
}

func runPrivEscDetection() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tid int
		if rows.Scan(&tid) == nil {
			detectWindowsPrivEsc(tid)
			detectLinuxPrivEsc(tid)
		}
	}
}

// ── Windows: privileged group membership changes ──────────────────────────────

var winPrivEscEventIDs = []struct {
	id       string
	desc     string
	severity string
	mitre    string
}{
	{"4728", "Member added to global security group",    "high",   "T1098"},
	{"4732", "Member added to local security group",     "high",   "T1098"},
	{"4756", "Member added to universal security group", "high",   "T1098"},
	{"4720", "New local user account created",           "high",   "T1136.001"},
	{"4672", "Special privileges assigned at logon",     "medium", "T1134"},
}

func detectWindowsPrivEsc(tenantID int) {
	for _, ev := range winPrivEscEventIDs {
		rows, err := database.DB.Query(`
			SELECT el.agent_id,
			       el.log_message,
			       el.parsed_fields->>'user' AS username
			FROM endpoint_logs el
			JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
			WHERE el.parsed_fields->>'event_id' = $2
			  AND el.created_at > NOW() - INTERVAL '5 minutes'
			LIMIT 50
		`, tenantID, ev.id)
		if err != nil {
			continue
		}

		for rows.Next() {
			var agentID int
			var logMsg, username string
			_ = username
			if rows.Scan(&agentID, &logMsg, &username) != nil {
				continue
			}
			subject := username
			if subject == "" {
				subject = fmt.Sprintf("agent%d", agentID)
			}
			key := fmt.Sprintf("%d:wpe:%s:%s", tenantID, ev.id, subject)
			if privescDedup.touched(key) {
				continue
			}
			privescDedup.touch(key)
			msg := fmt.Sprintf("Windows privilege escalation — EventID %s (%s): user=%s | %s",
				ev.id, ev.desc, subject, truncateLog(logMsg, 300))
			log.Printf("[PrivEsc] %s", msg)
			CreateAlert(models.Alert{
				AgentID:        agentID,
				TenantID:       tenantID,
				Severity:       ev.severity,
				RuleName:       "Privilege Escalation — " + ev.desc,
				LogMessage:     msg,
				MitreTactic:    "Privilege Escalation",
				MitreTechnique: ev.mitre,
				MitreName:      "Account Manipulation",
				Fingerprint:    fmt.Sprintf("privesc-win-%s-%s", ev.id, subject),
			})
		}
		rows.Close()
	}
}

// ── Linux: syslog patterns ────────────────────────────────────────────────────

type linuxPrivEscPattern struct {
	needle   string
	ruleName string
	severity string
	mitre    string
	desc     string
}

var linuxPrivEscPatterns = []linuxPrivEscPattern{
	{
		needle:   "sudo",
		ruleName: "Sudo Command Executed",
		severity: "medium",
		mitre:    "T1548.003",
		desc:     "Sudo or Sudoers Abuse",
	},
	{
		needle:   "su to root",
		ruleName: "Switch User to Root",
		severity: "high",
		mitre:    "T1548",
		desc:     "Abuse Elevation Control Mechanism",
	},
	{
		needle:   "/etc/sudoers",
		ruleName: "Sudoers Policy Modified",
		severity: "critical",
		mitre:    "T1548.003",
		desc:     "Sudo and Sudo Caching",
	},
	{
		needle:   "/etc/passwd",
		ruleName: "Passwd Database Modified",
		severity: "high",
		mitre:    "T1136.001",
		desc:     "Create Account: Local Account",
	},
	{
		needle:   "chmod +s",
		ruleName: "SUID Bit Set",
		severity: "high",
		mitre:    "T1548.001",
		desc:     "Setuid and Setgid",
	},
	{
		needle:   "chmod u+s",
		ruleName: "SUID Bit Set",
		severity: "high",
		mitre:    "T1548.001",
		desc:     "Setuid and Setgid",
	},
	{
		needle:   "chmod g+s",
		ruleName: "SGID Bit Set",
		severity: "high",
		mitre:    "T1548.001",
		desc:     "Setuid and Setgid",
	},
}

func detectLinuxPrivEsc(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id, el.log_message, el.parsed_fields->>'user' AS username
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.created_at > NOW() - INTERVAL '5 minutes'
		  AND el.parsed_fields->>'event_id' IS NULL
		LIMIT 2000
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var logMsg, username string
		if rows.Scan(&agentID, &logMsg, &username) != nil {
			continue
		}
		lower := strings.ToLower(logMsg)

		for _, pat := range linuxPrivEscPatterns {
			if !strings.Contains(lower, pat.needle) {
				continue
			}
			subject := username
			if subject == "" {
				subject = extractUsernameFromLog(logMsg)
			}
			if subject == "" {
				subject = fmt.Sprintf("agent%d", agentID)
			}
			key := fmt.Sprintf("%d:lpe:%s:%s", tenantID, pat.needle, subject)
			if privescDedup.touched(key) {
				continue
			}
			privescDedup.touch(key)
			msg := fmt.Sprintf("Linux privilege escalation — %s: user=%s | %s",
				pat.ruleName, subject, truncateLog(logMsg, 300))
			log.Printf("[PrivEsc] %s", msg)
			CreateAlert(models.Alert{
				AgentID:        agentID,
				TenantID:       tenantID,
				Severity:       pat.severity,
				RuleName:       pat.ruleName,
				LogMessage:     msg,
				MitreTactic:    "Privilege Escalation",
				MitreTechnique: pat.mitre,
				MitreName:      pat.desc,
				Fingerprint:    fmt.Sprintf("privesc-linux-%s-%s", pat.needle, subject),
			})
			break // one pattern match per log line is enough
		}
	}
}

func truncateLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
