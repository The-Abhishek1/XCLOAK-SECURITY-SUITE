package services

// Persistence Detector
//
// Detects attacker-established persistence mechanisms on Windows and Linux.
//
// Windows patterns (via EventID from parsed_fields):
//   4698 / 4702  — Scheduled task created or modified
//   7045         — New Windows service installed
//   4657         — Registry value modified (Run/RunOnce/RunServices keys)
//   4720         — New user account created (also in privesc detector, different focus)
//   Sysmon 11    — File created in startup/appdata/temp paths
//
// Linux patterns (from log_message text):
//   crontab -e / cron.d / crontabs  — cron job creation
//   systemctl enable / systemd service files in /etc/systemd/system
//   /etc/rc.local, /etc/profile.d/  — shell startup file modification
//   ~/.bashrc, ~/.bash_profile       — user shell init modification
//   /etc/init.d/                     — SysV init script
//
// Windows registry Run keys (via Sysmon EventID 13 or EventID 4657):
//   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
//   HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
//   HKLM\SYSTEM\CurrentControlSet\Services
//
// Runs every 5 minutes. Alert dedup TTL: 30 minutes per (agentID, mechanism, subject).

import (
	"fmt"
	"log"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

const persistDedupTTL = 30 * time.Minute

var persistDedup = newTTLMap(persistDedupTTL)

// Suspicious scheduled task / service binary path patterns
var suspiciousPaths = []string{
	`\temp\`, `\tmp\`, `\appdata\`, `\appdata\roaming\`,
	`\users\public\`, `\programdata\`,
	`\downloads\`, `\desktop\`,
	"/tmp/", "/var/tmp/", "/dev/shm/",
	"powershell", "cmd.exe", "wscript", "cscript", "mshta",
	"regsvr32", "rundll32", "certutil",
}

// Persistence run-key prefixes
var persistenceRunKeys = []string{
	`software\microsoft\windows\currentversion\run`,
	`software\microsoft\windows\currentversion\runonce`,
	`software\microsoft\windows\currentversion\runservices`,
	`system\currentcontrolset\services`,
	`software\microsoft\windows nt\currentversion\winlogon`,
	`software\microsoft\windows\currentversion\policies\explorer\run`,
}

func StartPersistenceScheduler() {
	go func() {
		time.Sleep(4 * time.Minute)
		for {
			runPersistenceDetection()
			time.Sleep(5 * time.Minute)
		}
	}()
}

func runPersistenceDetection() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tid int
		if rows.Scan(&tid) == nil {
			detectScheduledTasks(tid)
			detectNewServices(tid)
			detectRegistryPersistence(tid)
			detectLinuxPersistence(tid)
		}
	}
}

// ── 1. Scheduled task creation (EventID 4698/4702) ────────────────────────────

func detectScheduledTasks(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'user'         AS username,
		       el.parsed_fields->>'service_name' AS task_name,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'event_id' IN ('4698','4702')
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		LIMIT 500
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var username, taskName, logMsg string
		if rows.Scan(&agentID, &username, &taskName, &logMsg) != nil {
			continue
		}

		// Elevated severity if task references suspicious paths
		severity := "medium"
		lowerMsg := strings.ToLower(logMsg)
		for _, p := range suspiciousPaths {
			if strings.Contains(lowerMsg, p) {
				severity = "high"
				break
			}
		}

		subject := taskName
		if subject == "" {
			subject = username
		}
		key := fmt.Sprintf("%d:persist-task:%d:%s", tenantID, agentID, subject)
		if persistDedup.touched(key) {
			continue
		}
		persistDedup.touch(key)

		msg := fmt.Sprintf("Scheduled task created by '%s' on agent %d: task='%s' | %s",
			username, agentID, taskName, truncateLog(logMsg, 300))
		log.Printf("[Persist] %s", msg)
		CreateAlert(models.Alert{
			AgentID:        agentID,
			TenantID:       tenantID,
			Severity:       severity,
			RuleName:       "Persistence — Scheduled Task Created",
			LogMessage:     msg,
			MitreTactic:    "Persistence",
			MitreTechnique: "T1053.005",
			MitreName:      "Scheduled Task",
			Fingerprint:    fmt.Sprintf("persist-task-%d-%s", agentID, subject),
		})
	}
}

// ── 2. New Windows service (EventID 7045) ─────────────────────────────────────

func detectNewServices(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'service_name' AS svc_name,
		       el.parsed_fields->>'service_type' AS svc_type,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'event_id' = '7045'
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		LIMIT 500
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var svcName, svcType, logMsg string
		if rows.Scan(&agentID, &svcName, &svcType, &logMsg) != nil {
			continue
		}

		severity := "medium"
		lowerMsg := strings.ToLower(logMsg + " " + svcName)
		for _, p := range suspiciousPaths {
			if strings.Contains(lowerMsg, p) {
				severity = "critical"
				break
			}
		}

		key := fmt.Sprintf("%d:persist-svc:%d:%s", tenantID, agentID, svcName)
		if persistDedup.touched(key) {
			continue
		}
		persistDedup.touch(key)

		msg := fmt.Sprintf("New Windows service installed on agent %d: name='%s' type='%s' | %s",
			agentID, svcName, svcType, truncateLog(logMsg, 300))
		log.Printf("[Persist] %s", msg)
		CreateAlert(models.Alert{
			AgentID:        agentID,
			TenantID:       tenantID,
			Severity:       severity,
			RuleName:       "Persistence — New Windows Service",
			LogMessage:     msg,
			MitreTactic:    "Persistence",
			MitreTechnique: "T1543.003",
			MitreName:      "Windows Service",
			Fingerprint:    fmt.Sprintf("persist-svc-%d-%s", agentID, svcName),
		})
	}
}

// ── 3. Registry Run key persistence (EventID 4657 / Sysmon 13) ───────────────

func detectRegistryPersistence(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       lower(el.parsed_fields->>'registry_key') AS reg_key,
		       el.parsed_fields->>'registry_value'       AS reg_val,
		       el.parsed_fields->>'user'                 AS username,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'event_id' IN ('4657','13')
		  AND el.parsed_fields->>'registry_key' IS NOT NULL
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		LIMIT 1000
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var regKey, regVal, username, logMsg string
		if rows.Scan(&agentID, &regKey, &regVal, &username, &logMsg) != nil {
			continue
		}

		matched := false
		for _, runKey := range persistenceRunKeys {
			if strings.Contains(regKey, runKey) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		key := fmt.Sprintf("%d:persist-reg:%d:%s", tenantID, agentID, regKey)
		if persistDedup.touched(key) {
			continue
		}
		persistDedup.touch(key)

		msg := fmt.Sprintf("Registry Run key modified on agent %d by '%s': key='%s' value='%s'",
			agentID, username, regKey, truncateLog(regVal, 200))
		log.Printf("[Persist] %s", msg)
		CreateAlert(models.Alert{
			AgentID:        agentID,
			TenantID:       tenantID,
			Severity:       "high",
			RuleName:       "Persistence — Registry Run Key",
			LogMessage:     msg,
			MitreTactic:    "Persistence",
			MitreTechnique: "T1547.001",
			MitreName:      "Registry Run Keys / Startup Folder",
			Fingerprint:    fmt.Sprintf("persist-reg-%d-%s", agentID, regKey[:min(20, len(regKey))]),
		})
	}
}

// ── 4. Linux persistence — cron, systemd, init, profile ────────────────────

type linuxPersistPat struct {
	needle   string
	ruleName string
	severity string
	mitre    string
}

var linuxPersistPats = []linuxPersistPat{
	{"crontab -e",          "Crontab Modified",             "high",     "T1053.003"},
	{"/etc/cron.",          "System Cron Job Modified",     "high",     "T1053.003"},
	{"/var/spool/cron",     "User Crontab Modified",        "high",     "T1053.003"},
	{"systemctl enable",    "Systemd Service Enabled",      "medium",   "T1543.002"},
	{"/etc/systemd/system", "Systemd Unit File Created",    "high",     "T1543.002"},
	{"/etc/init.d/",        "SysV Init Script Modified",    "high",     "T1543.002"},
	{"/etc/rc.local",       "rc.local Modified",            "high",     "T1037.004"},
	{"/etc/profile.d/",     "Profile.d Script Added",       "high",     "T1037.004"},
	{"~/.bashrc",           "User .bashrc Modified",        "medium",   "T1546.004"},
	{"~/.bash_profile",     "User .bash_profile Modified",  "medium",   "T1546.004"},
	{"/etc/profile",        "/etc/profile Modified",        "high",     "T1037.004"},
	{"/etc/passwd",         "Passwd File Modified (new user?)","high",  "T1136.001"},
}

func detectLinuxPersistence(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id, el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.created_at > NOW() - INTERVAL '5 minutes'
		  AND el.parsed_fields->>'event_id' IS NULL
		LIMIT 5000
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var logMsg string
		if rows.Scan(&agentID, &logMsg) != nil {
			continue
		}
		lower := strings.ToLower(logMsg)

		for _, pat := range linuxPersistPats {
			if !strings.Contains(lower, pat.needle) {
				continue
			}
			key := fmt.Sprintf("%d:persist-linux:%d:%s", tenantID, agentID, pat.needle)
			if persistDedup.touched(key) {
				break
			}
			persistDedup.touch(key)

			msg := fmt.Sprintf("Linux persistence — %s on agent %d: %s",
				pat.ruleName, agentID, truncateLog(logMsg, 300))
			log.Printf("[Persist] %s", msg)
			CreateAlert(models.Alert{
				AgentID:        agentID,
				TenantID:       tenantID,
				Severity:       pat.severity,
				RuleName:       "Persistence — " + pat.ruleName,
				LogMessage:     msg,
				MitreTactic:    "Persistence",
				MitreTechnique: pat.mitre,
				MitreName:      "Boot or Logon Initialization Scripts",
				Fingerprint:    fmt.Sprintf("persist-linux-%d-%s", agentID, pat.needle[:min(15, len(pat.needle))]),
			})
			break
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
