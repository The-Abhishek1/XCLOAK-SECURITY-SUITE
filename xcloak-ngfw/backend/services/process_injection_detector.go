package services

// Process Injection & Memory Attack Detector
//
// Analyses Sysmon and Windows Security event logs for in-memory attack
// techniques that bypass disk-based detection.  These are the primary
// evasion path for APTs and advanced ransomware (Cobalt Strike, Meterpreter,
// Sliver, Brute Ratel, etc.).
//
// Sysmon must be installed on monitored hosts and configured to log EventIDs
// 8, 10, and 25 (included in the SwiftOnSecurity / olafhartong configs).
//
// Detection categories:
//
//  CreateRemoteThread     (T1055.003) — Sysmon EventID 8: a process created a
//                                       thread in another process' address space.
//                                       High-confidence indicator of code injection.
//
//  LSASS Memory Access    (T1003.001) — Sysmon EventID 10: a non-system process
//                                       opened lsass.exe with credential-read
//                                       access masks (0x1010/0x1410/0x143a/0x1fffff).
//                                       Catches mimikatz, procdump, Cobalt Strike
//                                       credential extraction.
//
//  Process Hollowing      (T1055.012) — Sysmon EventID 25 (ProcessTampering):
//                                       legitimate process image replaced in memory.
//
//  Suspicious ProcessAccess (T1055)  — Sysmon EventID 10: unusual process (not
//                                       security tools) reading another process'
//                                       memory with PROCESS_VM_READ.
//
//  Reflective DLL Load    (T1055.001) — Sysmon EventID 7 (ImageLoad):
//                                       unsigned DLL loaded from %TEMP%, %APPDATA%,
//                                       or user writable paths.
//
//  Process Masquerading   (T1036.005) — EventID 4688 / Sysmon EventID 1:
//                                       known system binary running from wrong path
//                                       (svchost.exe outside System32, etc.).
//
//  Credential Dumping — SAM (T1003.002) — reg save/copy of HKLM\SAM or SYSTEM hive.
//
//  Credential Dumping — NTDS (T1003.003) — ntdsutil.exe, vssadmin shadow copy of
//                                           NTDS.dit accessed.
//
// Runs every 5 minutes. Dedup TTL: 15 minutes per (tenant, technique, source).

import (
	"fmt"
	"log"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

var injDedup = newTTLMap(15 * time.Minute)

func StartProcessInjectionScheduler() {
	go func() {
		time.Sleep(110 * time.Second)
		for {
			runProcessInjectionDetection()
			time.Sleep(5 * time.Minute)
		}
	}()
}

func runProcessInjectionDetection() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tid int
		if rows.Scan(&tid) == nil {
			detectCreateRemoteThread(tid)
			detectLSASSAccess(tid)
			detectProcessHollowing(tid)
			detectReflectiveDLL(tid)
			detectProcessMasquerade(tid)
			detectSAMDump(tid)
			detectNTDSDump(tid)
		}
	}
}

// detectCreateRemoteThread — Sysmon EventID 8 (CreateRemoteThread).
// Any process creating a remote thread in another is highly suspicious.
func detectCreateRemoteThread(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       coalesce(el.parsed_fields->>'user','') AS user,
		       coalesce(el.parsed_fields->>'src_ip','') AS src_ip,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'event_id' = '8'
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		  AND el.log_message NOT ILIKE '%msiexec%'
		  AND el.log_message NOT ILIKE '%werfault%'
		LIMIT 100
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var agentID int
		var user, srcIP, msg string
		if rows.Scan(&agentID, &user, &srcIP, &msg) != nil {
			continue
		}

		// Extract source and target process names for the alert message
		source := extractSysmonField(msg, "SourceImage")
		target := extractSysmonField(msg, "TargetImage")

		key := fmt.Sprintf("%d:crt:%s:%s", tenantID, source, target)
		if injDedup.touched(key) {
			continue
		}
		injDedup.touch(key)
		m := fmt.Sprintf("CreateRemoteThread — injector='%s' target='%s' user='%s' (possible Cobalt Strike/Metasploit DLL injection)",
			source, target, user)
		log.Printf("[Inject] %s", m)
		createInjAlert(agentID, tenantID, "critical", "Process Injection — CreateRemoteThread (T1055.003)", m, "T1055.003", "Thread Execution Hijacking")
	}
}

// detectLSASSAccess — Sysmon EventID 10 with lsass.exe as target.
// Common GrantedAccess values used by credential dumpers:
//   0x1010 (PROCESS_QUERY_INFORMATION|PROCESS_VM_READ) — generic read
//   0x1410 (adds PROCESS_DUP_HANDLE)
//   0x143a (Cobalt Strike default)
//   0x1fffff (all access)
func detectLSASSAccess(tenantID int) {
	credDumpMasks := []string{"0x1010", "0x1410", "0x143a", "0x40", "0x1fffff", "0x1f3fff", "0xffff"}
	for _, mask := range credDumpMasks {
		rows, err := database.DB.Query(`
			SELECT el.agent_id,
			       coalesce(el.parsed_fields->>'user','') AS user,
			       el.log_message
			FROM endpoint_logs el
			JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
			WHERE el.parsed_fields->>'event_id' = '10'
			  AND el.created_at > NOW() - INTERVAL '5 minutes'
			  AND el.log_message ILIKE '%lsass.exe%'
			  AND el.log_message ILIKE $2
			LIMIT 50
		`, tenantID, "%"+mask+"%")
		if err != nil {
			continue
		}
		for rows.Next() {
			var agentID int
			var user, msg string
			if rows.Scan(&agentID, &user, &msg) != nil {
				continue
			}
			source := extractSysmonField(msg, "SourceImage")
			// Whitelist legitimate security products
			if isLSASSWhitelisted(source) {
				continue
			}
			key := fmt.Sprintf("%d:lsass:%s:%s", tenantID, source, mask)
			if injDedup.touched(key) {
				break
			}
			injDedup.touch(key)
			m := fmt.Sprintf("LSASS Credential Dump — source='%s' access_mask='%s' user='%s' (mimikatz/procdump/Cobalt Strike)", source, mask, user)
			log.Printf("[Inject] %s", m)
			createInjAlert(agentID, tenantID, "critical", "LSASS Memory Access — Credential Dumping (T1003.001)", m, "T1003.001", "LSASS Memory")
		}
		rows.Close()
	}
}

// detectProcessHollowing — Sysmon EventID 25 (ProcessTampering).
func detectProcessHollowing(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       coalesce(el.parsed_fields->>'user','') AS user,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'event_id' = '25'
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		LIMIT 50
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var agentID int
		var user, msg string
		if rows.Scan(&agentID, &user, &msg) != nil {
			continue
		}
		image := extractSysmonField(msg, "Image")
		key := fmt.Sprintf("%d:hollow:%s", tenantID, image)
		if injDedup.touched(key) {
			continue
		}
		injDedup.touch(key)
		m := fmt.Sprintf("Process Hollowing — target='%s' user='%s' (legitimate process image replaced in memory)", image, user)
		log.Printf("[Inject] %s", m)
		createInjAlert(agentID, tenantID, "critical", "Process Hollowing Detected (T1055.012)", m, "T1055.012", "Process Hollowing")
	}
}

// detectReflectiveDLL — Sysmon EventID 7 (ImageLoad): unsigned DLL from user-writable path.
func detectReflectiveDLL(tenantID int) {
	suspiciousPaths := []string{`\temp\`, `\tmp\`, `\appdata\`, `\users\public\`, `\programdata\`, `\desktop\`}
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       coalesce(el.parsed_fields->>'user','') AS user,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'event_id' = '7'
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		  AND (
		       el.log_message ILIKE '%signed: false%'
		    OR el.log_message ILIKE '%signature: --%'
		    OR el.log_message ILIKE '%not validated%'
		  )
		LIMIT 200
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var agentID int
		var user, msg string
		if rows.Scan(&agentID, &user, &msg) != nil {
			continue
		}
		msgLow := strings.ToLower(msg)
		for _, path := range suspiciousPaths {
			if strings.Contains(msgLow, path) {
				imagePath := extractSysmonField(msg, "ImageLoaded")
				key := fmt.Sprintf("%d:rdll:%s", tenantID, imagePath)
				if injDedup.touched(key) {
					break
				}
				injDedup.touch(key)
				m := fmt.Sprintf("Unsigned DLL from Suspicious Path — dll='%s' path='%s' user='%s' (possible reflective load)", imagePath, path, user)
				log.Printf("[Inject] %s", m)
				createInjAlert(agentID, tenantID, "high", "Reflective DLL Load — Unsigned from User Path (T1055.001)", m, "T1055.001", "Dynamic-link Library Injection")
				break
			}
		}
	}
}

// detectProcessMasquerade — system binary running from wrong path.
var masqueradeBinaries = map[string]string{
	"svchost.exe":      `\system32\`,
	"lsass.exe":        `\system32\`,
	"csrss.exe":        `\system32\`,
	"wininit.exe":      `\system32\`,
	"winlogon.exe":     `\system32\`,
	"services.exe":     `\system32\`,
	"smss.exe":         `\system32\`,
	"taskhost.exe":     `\system32\`,
	"explorer.exe":     `\windows\`,
	"spoolsv.exe":      `\system32\`,
}

func detectProcessMasquerade(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       coalesce(el.parsed_fields->>'user','') AS user,
		       lower(el.parsed_fields->>'image') AS image,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'event_id' IN ('1','4688')
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		  AND el.parsed_fields->>'image' IS NOT NULL
		LIMIT 2000
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var agentID int
		var user, image, msg string
		if rows.Scan(&agentID, &user, &image, &msg) != nil {
			continue
		}
		for binName, validPath := range masqueradeBinaries {
			if !strings.HasSuffix(image, strings.ToLower(binName)) {
				continue
			}
			if strings.Contains(image, validPath) {
				break
			}
			// Binary name matches but path is wrong
			key := fmt.Sprintf("%d:masq:%s", tenantID, image)
			if injDedup.touched(key) {
				break
			}
			injDedup.touch(key)
			m := fmt.Sprintf("Process Masquerading — binary='%s' runs from wrong path (expected '%s') user='%s' (T1036.005)", image, validPath, user)
			log.Printf("[Inject] %s", m)
			createInjAlert(agentID, tenantID, "high", "Process Masquerading — Wrong Path (T1036.005)", m, "T1036.005", "Match Legitimate Name or Location")
			break
		}
	}
}

// detectSAMDump — reg save/copy of SAM or SYSTEM hive.
func detectSAMDump(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       coalesce(el.parsed_fields->>'user','') AS user,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.created_at > NOW() - INTERVAL '5 minutes'
		  AND (
		       el.log_message ILIKE '%hklm\sam%'
		    OR el.log_message ILIKE '%hklm\\system%'
		    OR el.log_message ILIKE '%hklm\security%'
		    OR el.log_message ILIKE '%reg save%sam%'
		    OR el.log_message ILIKE '%reg copy%sam%'
		    OR el.log_message ILIKE '%ntdsutil%'
		  )
		LIMIT 50
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var agentID int
		var user, msg string
		if rows.Scan(&agentID, &user, &msg) != nil {
			continue
		}
		key := fmt.Sprintf("%d:samdump:%s", tenantID, user)
		if injDedup.touched(key) {
			continue
		}
		injDedup.touch(key)
		m := fmt.Sprintf("SAM/SYSTEM Hive Dump — user='%s' context='%s'", user, truncateLog(msg, 200))
		log.Printf("[Inject] %s", m)
		createInjAlert(agentID, tenantID, "critical", "SAM Credential Dump — Registry Hive (T1003.002)", m, "T1003.002", "Security Account Manager")
	}
}

// detectNTDSDump — ntdsutil, VSS shadow copy accessing NTDS.dit.
func detectNTDSDump(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       coalesce(el.parsed_fields->>'user','') AS user,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.created_at > NOW() - INTERVAL '5 minutes'
		  AND (
		       el.log_message ILIKE '%ntdsutil%'
		    OR el.log_message ILIKE '%ntds.dit%'
		    OR (el.log_message ILIKE '%vssadmin%' AND el.log_message ILIKE '%ntds%')
		  )
		LIMIT 50
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var agentID int
		var user, msg string
		if rows.Scan(&agentID, &user, &msg) != nil {
			continue
		}
		key := fmt.Sprintf("%d:ntds:%s", tenantID, user)
		if injDedup.touched(key) {
			continue
		}
		injDedup.touch(key)
		m := fmt.Sprintf("NTDS.dit Credential Dump — user='%s' context='%s' (possible full AD hash extraction)", user, truncateLog(msg, 200))
		log.Printf("[Inject] %s", m)
		createInjAlert(agentID, tenantID, "critical", "NTDS.dit Dump — Full AD Credential Extract (T1003.003)", m, "T1003.003", "NTDS")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func extractSysmonField(msg, field string) string {
	lower := strings.ToLower(msg)
	lfield := strings.ToLower(field) + ":"
	idx := strings.Index(lower, lfield)
	if idx < 0 {
		return ""
	}
	rest := msg[idx+len(lfield):]
	rest = strings.TrimSpace(rest)
	end := strings.IndexAny(rest, "\n\r,")
	if end > 0 {
		rest = rest[:end]
	}
	if len(rest) > 120 {
		rest = rest[:120]
	}
	return strings.TrimSpace(rest)
}

// isLSASSWhitelisted excludes known-legitimate sources of LSASS access.
func isLSASSWhitelisted(source string) bool {
	src := strings.ToLower(source)
	whitelist := []string{
		"mssense.exe", "microsoft defender", "antimalware", "crowdstrike",
		"carbonblack", "cb.exe", "sentinelone", "cylance", "sophosav",
		"wmiprvse.exe", "svchost.exe",
	}
	for _, w := range whitelist {
		if strings.Contains(src, w) {
			return true
		}
	}
	return false
}

func createInjAlert(agentID, tenantID int, severity, rule, msg, mitre, mitreName string) {
	CreateAlert(models.Alert{
		AgentID:        agentID,
		TenantID:       tenantID,
		Severity:       severity,
		RuleName:       rule,
		LogMessage:     msg,
		MitreTactic:    injectionTactic(mitre),
		MitreTechnique: mitre,
		MitreName:      mitreName,
		Fingerprint:    fmt.Sprintf("inject-%s-%d", mitre, tenantID),
	})
}

func injectionTactic(mitre string) string {
	switch {
	case strings.HasPrefix(mitre, "T1003"):
		return "Credential Access"
	case strings.HasPrefix(mitre, "T1036"):
		return "Defense Evasion"
	default:
		return "Defense Evasion"
	}
}
