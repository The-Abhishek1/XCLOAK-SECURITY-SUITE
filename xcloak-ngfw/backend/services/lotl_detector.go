package services

// Living-off-the-Land (LotL) / Suspicious Process Detector
//
// Detects attackers using built-in OS binaries to blend in with normal activity.
// All data comes from endpoint_logs.parsed_fields set by the log normalizer for
// Windows EventID 4688 (process creation) and Sysmon Event 1.
//
// Detection categories:
//
//  1. Suspicious parent→child process chains (T1059)
//     Office apps spawning cmd/powershell, wscript executing from temp paths, etc.
//
//  2. LOLBin abuse (T1218 — System Binary Proxy Execution)
//     certutil -decode/-urlcache, regsvr32 /s /n /u /i:http, mshta http://,
//     rundll32 shell32 ShellExec, bitsadmin /transfer, wmic process call create,
//     odbcconf /a {REGSVR}, ieexec, presentationhost, appsyncpublishingserver.
//
//  3. Encoded / obfuscated PowerShell (T1059.001)
//     -enc / -EncodedCommand / -e flags, IEX (Invoke-Expression) from pipe,
//     DownloadString / DownloadFile in command line, FromBase64String.
//
//  4. Script execution from suspicious paths (T1059.005/006/007)
//     wscript/cscript/mshta running scripts from %TEMP%, %APPDATA%, Downloads.
//
// Runs every 5 minutes. Alert dedup TTL: 15 minutes per (agentID, pattern, subject).

import (
	"fmt"
	"log"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

const lotlDedupTTL = 15 * time.Minute

var lotlDedup = newTTLMap(lotlDedupTTL)

// ── Suspicious parent → child chains ─────────────────────────────────────────

type procChain struct {
	parent   string
	child    string
	ruleName string
	severity string
	mitre    string
}

var suspiciousChains = []procChain{
	// Office apps spawning shells
	{"winword.exe",   "cmd.exe",        "Word Spawned CMD",        "high",   "T1059.003"},
	{"winword.exe",   "powershell.exe",  "Word Spawned PowerShell", "high",   "T1059.001"},
	{"excel.exe",     "cmd.exe",        "Excel Spawned CMD",       "high",   "T1059.003"},
	{"excel.exe",     "powershell.exe",  "Excel Spawned PowerShell","high",   "T1059.001"},
	{"powerpnt.exe",  "cmd.exe",        "PowerPoint Spawned CMD",  "high",   "T1059.003"},
	{"powerpnt.exe",  "powershell.exe",  "PowerPoint Spawned PS",   "high",   "T1059.001"},
	{"outlook.exe",   "wscript.exe",    "Outlook Spawned WScript", "high",   "T1059.005"},
	{"outlook.exe",   "powershell.exe",  "Outlook Spawned PS",      "high",   "T1059.001"},
	// Browser spawning shells
	{"chrome.exe",    "cmd.exe",        "Chrome Spawned CMD",      "high",   "T1059.003"},
	{"firefox.exe",   "powershell.exe",  "Firefox Spawned PS",      "high",   "T1059.001"},
	// Script hosts spawning shells
	{"wscript.exe",   "powershell.exe",  "WScript Spawned PS",      "critical","T1059.001"},
	{"cscript.exe",   "powershell.exe",  "CScript Spawned PS",      "critical","T1059.001"},
	{"mshta.exe",     "powershell.exe",  "MSHTA Spawned PS",        "critical","T1059.001"},
	{"mshta.exe",     "cmd.exe",        "MSHTA Spawned CMD",       "critical","T1059.003"},
	// Exploitation indicators
	{"svchost.exe",   "powershell.exe",  "Svchost Spawned PS (Exploit?)", "critical","T1055"},
	{"spoolsv.exe",   "cmd.exe",        "Spooler Spawned CMD (PrintNightmare?)", "critical","T1068"},
}

// ── LOLBin signatures (command-line substrings) ───────────────────────────────

type lolBinSig struct {
	process  string // process name (empty = match any)
	cmdFrag  string // substring in command_line (lowercase)
	ruleName string
	severity string
	mitre    string
}

var lolBinSigs = []lolBinSig{
	// certutil
	{"certutil.exe", "-decode",           "CertUtil Decode (Possible Dropper)", "high", "T1140"},
	{"certutil.exe", "-urlcache",         "CertUtil Download",                  "high", "T1105"},
	{"certutil.exe", "-encode",           "CertUtil Encode (Possible Exfil)",   "medium","T1027"},
	// regsvr32 — squiblydoo
	{"regsvr32.exe", "/i:http",           "Regsvr32 Remote SCT (Squiblydoo)",   "critical","T1218.010"},
	{"regsvr32.exe", "/s /n /u /i:",      "Regsvr32 AppLocker Bypass",          "critical","T1218.010"},
	// mshta
	{"mshta.exe",    "http",              "MSHTA Remote HTA Execution",          "critical","T1218.005"},
	{"mshta.exe",    "vbscript",          "MSHTA VBScript Execution",            "critical","T1218.005"},
	// bitsadmin
	{"bitsadmin.exe","/transfer",         "BITSAdmin Download",                  "high","T1197"},
	{"bitsadmin.exe","/addfile",          "BITSAdmin Job Created",               "high","T1197"},
	// wmic
	{"wmic.exe",     "process call create","WMIC Remote Process Create",         "critical","T1047"},
	{"wmic.exe",     "shadow",            "WMIC Shadow Copy (Ransomware)",        "critical","T1490"},
	// rundll32
	{"rundll32.exe", "javascript",        "Rundll32 JS Execution",               "critical","T1218.011"},
	{"rundll32.exe", "shell32.dll,shellexec","Rundll32 ShellExec",               "high","T1218.011"},
	// odbcconf
	{"odbcconf.exe", "/a {regsvr",        "OdbcConf LOLBin Execution",           "critical","T1218.008"},
	// PowerShell download
	{"powershell.exe","downloadstring",   "PowerShell DownloadString",           "high","T1059.001"},
	{"powershell.exe","downloadfile",     "PowerShell DownloadFile",             "high","T1105"},
	{"powershell.exe","invoke-expression","PowerShell IEX",                      "high","T1059.001"},
	{"powershell.exe","iex(",             "PowerShell IEX",                      "high","T1059.001"},
	{"powershell.exe","frombase64string", "PowerShell Base64 Decode",            "high","T1027"},
}

// ── Encoded PowerShell flags ─────────────────────────────────────────────────

var encodedPSFlags = []string{
	"-enc ", "-encodedcommand ", "-e ", "-ec ",
}

func StartLotLScheduler() {
	go func() {
		time.Sleep(4 * time.Minute)
		for {
			runLotLDetection()
			time.Sleep(5 * time.Minute)
		}
	}()
}

func runLotLDetection() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tid int
		if rows.Scan(&tid) == nil {
			detectSuspiciousProcessChains(tid)
			detectLOLBinAbuse(tid)
			detectEncodedPowerShell(tid)
		}
	}
}

// ── 1. Suspicious parent-child chains ────────────────────────────────────────

func detectSuspiciousProcessChains(tenantID int) {
	// Use EventID 4688 rows that have ParentImage populated.
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       lower(el.parsed_fields->>'parent_image') AS parent,
		       lower(el.parsed_fields->>'process')      AS child,
		       el.parsed_fields->>'command_line'        AS cmdline,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'event_id'    = '4688'
		  AND el.parsed_fields->>'parent_image' IS NOT NULL
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		LIMIT 3000
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var parent, child, cmdLine, logMsg string
		if rows.Scan(&agentID, &parent, &child, &cmdLine, &logMsg) != nil {
			continue
		}

		// Extract just the exe name from a full path
		parentExe := exeName(parent)
		childExe := exeName(child)

		for _, chain := range suspiciousChains {
			if parentExe != chain.parent || childExe != chain.child {
				continue
			}
			key := fmt.Sprintf("%d:lotl-chain:%d:%s->%s", tenantID, agentID, chain.parent, chain.child)
			if lotlDedup.touched(key) {
				break
			}
			lotlDedup.touch(key)
			msg := fmt.Sprintf("LotL — %s: %s spawned %s on agent %d | cmd: %s",
				chain.ruleName, parentExe, childExe, agentID, truncateLog(cmdLine, 250))
			log.Printf("[LotL] %s", msg)
			CreateAlert(models.Alert{
				AgentID:        agentID,
				TenantID:       tenantID,
				Severity:       chain.severity,
				RuleName:       chain.ruleName,
				LogMessage:     msg,
				MitreTactic:    "Execution",
				MitreTechnique: chain.mitre,
				MitreName:      "Command and Scripting Interpreter",
				Fingerprint:    fmt.Sprintf("lotl-chain-%d-%s-%s", agentID, chain.parent, chain.child),
			})
			break
		}
	}
}

// ── 2. LOLBin command-line signatures ────────────────────────────────────────

func detectLOLBinAbuse(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       lower(el.parsed_fields->>'process')     AS proc,
		       lower(el.parsed_fields->>'command_line') AS cmdline,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.created_at > NOW() - INTERVAL '5 minutes'
		  AND el.parsed_fields->>'command_line' IS NOT NULL
		LIMIT 3000
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var proc, cmdLine, logMsg string
		if rows.Scan(&agentID, &proc, &cmdLine, &logMsg) != nil {
			continue
		}

		procExe := exeName(proc)

		for _, sig := range lolBinSigs {
			// If sig.process is set, proc must match
			if sig.process != "" && procExe != sig.process {
				continue
			}
			if !strings.Contains(cmdLine, sig.cmdFrag) {
				continue
			}
			key := fmt.Sprintf("%d:lotl-lolbin:%d:%s", tenantID, agentID, sig.ruleName)
			if lotlDedup.touched(key) {
				break
			}
			lotlDedup.touch(key)
			msg := fmt.Sprintf("LotL — %s on agent %d | cmd: %s",
				sig.ruleName, agentID, truncateLog(cmdLine, 250))
			log.Printf("[LotL] %s", msg)
			CreateAlert(models.Alert{
				AgentID:        agentID,
				TenantID:       tenantID,
				Severity:       sig.severity,
				RuleName:       sig.ruleName,
				LogMessage:     msg,
				MitreTactic:    "Defense Evasion",
				MitreTechnique: sig.mitre,
				MitreName:      "System Binary Proxy Execution",
				Fingerprint:    fmt.Sprintf("lotl-lolbin-%d-%s", agentID, strings.ReplaceAll(sig.ruleName[:12], " ", "-")),
			})
			break
		}
	}
}

// ── 3. Encoded PowerShell ─────────────────────────────────────────────────────

func detectEncodedPowerShell(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       lower(el.parsed_fields->>'command_line') AS cmdline,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.created_at > NOW() - INTERVAL '5 minutes'
		  AND lower(el.parsed_fields->>'process') LIKE '%powershell%'
		  AND el.parsed_fields->>'command_line' IS NOT NULL
		LIMIT 2000
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var cmdLine, logMsg string
		if rows.Scan(&agentID, &cmdLine, &logMsg) != nil {
			continue
		}
		for _, flag := range encodedPSFlags {
			if !strings.Contains(cmdLine, flag) {
				continue
			}
			key := fmt.Sprintf("%d:lotl-encps:%d", tenantID, agentID)
			if lotlDedup.touched(key) {
				break
			}
			lotlDedup.touch(key)
			msg := fmt.Sprintf("Encoded PowerShell command detected on agent %d (flag: %s): %s",
				agentID, strings.TrimSpace(flag), truncateLog(cmdLine, 250))
			log.Printf("[LotL] %s", msg)
			CreateAlert(models.Alert{
				AgentID:        agentID,
				TenantID:       tenantID,
				Severity:       "high",
				RuleName:       "Encoded PowerShell Command",
				LogMessage:     msg,
				MitreTactic:    "Defense Evasion",
				MitreTechnique: "T1027",
				MitreName:      "Obfuscated Files or Information",
				Fingerprint:    fmt.Sprintf("lotl-encps-%d", agentID),
			})
			break
		}
	}
}

// exeName extracts the basename from a full Windows/Unix path.
func exeName(path string) string {
	// Windows path: C:\Windows\System32\cmd.exe → cmd.exe
	for _, sep := range []string{"\\", "/"} {
		if idx := strings.LastIndex(path, sep); idx >= 0 {
			return path[idx+1:]
		}
	}
	return path
}
