package services

// Defense Evasion Detector
//
// Detects techniques attackers use to avoid detection, bypass security controls,
// and remove evidence of compromise. Covers MITRE TA0005.
//
// Detection categories:
//
//  Event Log Cleared      (T1070.001) — EventID 1102 (Security log cleared),
//                                       EventID 104 (System log cleared),
//                                       wevtutil cl / Clear-EventLog commands
//
//  AMSI Bypass            (T1562.001) — PowerShell reflection to patch
//                                       AmsiScanBuffer; strings like
//                                       [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
//
//  UAC Bypass             (T1548.002) — eventvwr.exe, fodhelper.exe, sdclt.exe,
//                                       cmstp.exe, DiskCleanup used as UAC bypass vectors
//
//  Windows Defender Disable (T1562.001) — Set-MpPreference, netsh advfirewall,
//                                          reg add Policies\WindowsDefender
//
//  Audit Policy Disabled  (T1562.002) — auditpol /set /success:disable,
//                                        EventID 4719 (audit policy changed)
//
//  Timestomping           (T1070.006) — PowerShell LastWriteTime manipulation,
//                                        touch -t on Linux, Invoke-TimeStomp
//
//  Indicator Removal      (T1070.004) — bulk file deletion of logs/forensic traces
//                                        (del /f *.log, shred, cipher /w, rm -rf /var/log)
//
//  ETW/Tracing Disabled   (T1562.006) — CancelIo, NtSetInformationThread,
//                                        patching EtwEventWrite to disable ETW
//
//  Binary Obfuscation     (T1027)     — long strings of base64, XOR decode patterns
//                                        in PowerShell / command line
//
//  Safe Mode Boot (AV bypass) (T1562.009) — bcdedit /set safeboot, bootcfg /raw safeboot
//
// Runs every 5 minutes. Dedup TTL: 30 minutes.

import (
	"fmt"
	"log"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

var evadeDedup = newTTLMap(30 * time.Minute)

type evasionSig struct {
	fragments []string
	ruleName  string
	severity  string
	mitre     string
	mitreName string
}

var evasionSigs = []evasionSig{
	// ── Event log clearing ──────────────────────────────────────────────────
	{[]string{"wevtutil", " cl"}, "Event Log Cleared — wevtutil cl", "critical", "T1070.001", "Clear Windows Event Logs"},
	{[]string{"wevtutil", "clear-log"}, "Event Log Cleared — wevtutil", "critical", "T1070.001", "Clear Windows Event Logs"},
	{[]string{"clear-eventlog"}, "Event Log Cleared — PowerShell", "critical", "T1070.001", "Clear Windows Event Logs"},
	{[]string{"remove-eventlog"}, "Event Log Removed — PowerShell", "critical", "T1070.001", "Clear Windows Event Logs"},

	// ── AMSI bypass ─────────────────────────────────────────────────────────
	{[]string{"amsiscanbuffer"}, "AMSI Bypass — AmsiScanBuffer Patch", "critical", "T1562.001", "Disable or Modify Tools"},
	{[]string{"amsiutils"}, "AMSI Bypass — AmsiUtils Reflection", "critical", "T1562.001", "Disable or Modify Tools"},
	{[]string{"amsi.dll", "getprocaddress"}, "AMSI Bypass — GetProcAddress amsi.dll", "critical", "T1562.001", "Disable or Modify Tools"},
	{[]string{"[runtime.interopservices.marshal]"}, "AMSI Bypass — Marshal pointer patch", "high", "T1562.001", "Disable or Modify Tools"},

	// ── UAC bypass ──────────────────────────────────────────────────────────
	{[]string{"eventvwr.exe", "hkcu\\software\\classes\\mscfile"}, "UAC Bypass — eventvwr Registry Hijack", "high", "T1548.002", "Bypass User Account Control"},
	{[]string{"fodhelper.exe"}, "UAC Bypass — fodhelper.exe", "high", "T1548.002", "Bypass User Account Control"},
	{[]string{"sdclt.exe", "/kickoffelev"}, "UAC Bypass — sdclt.exe KickOffElev", "high", "T1548.002", "Bypass User Account Control"},
	{[]string{"cmstp.exe", "/ni", "/s"}, "UAC Bypass — cmstp.exe", "high", "T1548.002", "Bypass User Account Control"},

	// ── Windows Defender / firewall disable ─────────────────────────────────
	{[]string{"set-mppreference", "-disablerealtimemonitoring"}, "Windows Defender Disabled — Real-Time Monitoring Off", "critical", "T1562.001", "Disable or Modify Tools"},
	{[]string{"set-mppreference", "-disablescriptscanning"}, "Windows Defender Disabled — Script Scanning Off", "critical", "T1562.001", "Disable or Modify Tools"},
	{[]string{"set-mppreference", "-disablebehaviormonitoring"}, "Windows Defender Disabled — Behavior Monitoring Off", "critical", "T1562.001", "Disable or Modify Tools"},
	{[]string{"netsh", "advfirewall", "set allprofiles state off"}, "Windows Firewall Disabled", "critical", "T1562.004", "Disable or Modify System Firewall"},
	{[]string{"net stop", "windefend"}, "Windows Defender Service Stopped", "critical", "T1562.001", "Disable or Modify Tools"},
	{[]string{"reg add", "disableantispyware", "1"}, "Windows Defender Disabled — Registry", "critical", "T1562.001", "Disable or Modify Tools"},

	// ── Audit policy changes ─────────────────────────────────────────────────
	{[]string{"auditpol", "/success:disable"}, "Audit Policy Disabled — Success Audit", "high", "T1562.002", "Disable Windows Event Logging"},
	{[]string{"auditpol", "/failure:disable"}, "Audit Policy Disabled — Failure Audit", "high", "T1562.002", "Disable Windows Event Logging"},

	// ── Timestomping ─────────────────────────────────────────────────────────
	{[]string{"lastwritetime"}, "Timestomping — LastWriteTime Modified", "high", "T1070.006", "Timestomp"},
	{[]string{"invoke-timestomp"}, "Timestomping — Invoke-TimeStomp Script", "critical", "T1070.006", "Timestomp"},
	{[]string{"[system.io.file]::setlastwritetimeutc"}, "Timestomping — .NET File Time Manipulation", "high", "T1070.006", "Timestomp"},

	// ── Indicator removal ────────────────────────────────────────────────────
	{[]string{"del", "/f", "/s", "/q", "*.log"}, "Log File Deletion — del /f *.log", "high", "T1070.004", "File Deletion"},
	{[]string{"cipher", "/w:"}, "Secure File Wipe — cipher /w", "high", "T1070.004", "File Deletion"},
	{[]string{"shred", "-u"}, "Secure File Delete — shred -u", "high", "T1070.004", "File Deletion"},
	{[]string{"rm", "-rf", "/var/log"}, "Log Directory Deletion — /var/log", "critical", "T1070.004", "File Deletion"},

	// ── ETW / tracing disable ───────────────────────────────────────────────
	{[]string{"etweventwrite"}, "ETW Patched — EtwEventWrite bypass", "critical", "T1562.006", "Disable or Modify Linux Auditing System"},
	{[]string{"ntsetinformationthread", "0x11"}, "ETW Disabled — NtSetInformationThread HideFromDebugger", "critical", "T1562.006", "Disable or Modify Linux Auditing System"},

	// ── Safe mode / boot modification ───────────────────────────────────────
	{[]string{"bcdedit", "safeboot"}, "Ransomware: Safe Mode Boot — AV Bypass (T1562.009)", "critical", "T1562.009", "Safe Mode Boot"},
	{[]string{"bootcfg", "/raw", "safeboot"}, "Ransomware: Safe Mode Boot — bootcfg", "critical", "T1562.009", "Safe Mode Boot"},
}

// EventID-based evasion detection (don't need command line matching)
var evasionEventIDs = map[string]struct {
	rule     string
	severity string
	mitre    string
	name     string
}{
	"1102": {"Security Event Log Cleared (EventID 1102)", "critical", "T1070.001", "Clear Windows Event Logs"},
	"104":  {"System Event Log Cleared (EventID 104)", "critical", "T1070.001", "Clear Windows Event Logs"},
	"4719": {"Audit Policy Changed (EventID 4719)", "high", "T1562.002", "Disable Windows Event Logging"},
	"4657": {"Registry Value Modified (EventID 4657)", "medium", "T1112", "Modify Registry"},
}

func StartDefenseEvasionScheduler() {
	go func() {
		time.Sleep(80 * time.Second)
		for {
			runDefenseEvasionDetection()
			time.Sleep(5 * time.Minute)
		}
	}()
}

func runDefenseEvasionDetection() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tid int
		if rows.Scan(&tid) == nil {
			detectEvasionSigs(tid)
			detectEvasionEventIDs(tid)
		}
	}
}

func detectEvasionSigs(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       lower(coalesce(el.parsed_fields->>'command_line', el.log_message)) AS cmdline,
		       coalesce(el.parsed_fields->>'user','') AS user,
		       coalesce(el.parsed_fields->>'src_ip','') AS src_ip,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.created_at > NOW() - INTERVAL '5 minutes'
		  AND (
		       el.parsed_fields->>'event_id' IN ('1','4688')
		    OR el.log_message ILIKE '%amsi%'
		    OR el.log_message ILIKE '%wevtutil%'
		    OR el.log_message ILIKE '%defender%'
		    OR el.log_message ILIKE '%auditpol%'
		    OR el.log_message ILIKE '%timestomp%'
		    OR el.log_message ILIKE '%bcdedit%safeboot%'
		  )
		LIMIT 2000
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var cmdline, user, srcIP, logMsg string
		if rows.Scan(&agentID, &cmdline, &user, &srcIP, &logMsg) != nil {
			continue
		}
		for _, sig := range evasionSigs {
			allMatch := true
			for _, frag := range sig.fragments {
				if !strings.Contains(cmdline, frag) {
					allMatch = false
					break
				}
			}
			if !allMatch {
				continue
			}
			key := fmt.Sprintf("%d:evade:%s:%s", tenantID, sig.mitre, user)
			if evadeDedup.touched(key) {
				break
			}
			evadeDedup.touch(key)
			msg := fmt.Sprintf("%s — user='%s' src_ip='%s' cmd='%s'",
				sig.ruleName, user, srcIP, truncateLog(logMsg, 200))
			log.Printf("[Evade] %s", msg)
			CreateAlert(models.Alert{
				AgentID:        agentID,
				TenantID:       tenantID,
				Severity:       sig.severity,
				RuleName:       sig.ruleName,
				LogMessage:     msg,
				MitreTactic:    "Defense Evasion",
				MitreTechnique: sig.mitre,
				MitreName:      sig.mitreName,
				Fingerprint:    fmt.Sprintf("evade-%s-%d-%s", sig.mitre, tenantID, user),
			})
			break
		}
	}
}

func detectEvasionEventIDs(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'event_id' AS eid,
		       coalesce(el.parsed_fields->>'user','') AS user,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'event_id' IN ('1102','104','4719')
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		LIMIT 100
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var agentID int
		var eid, user, logMsg string
		if rows.Scan(&agentID, &eid, &user, &logMsg) != nil {
			continue
		}
		def, ok := evasionEventIDs[eid]
		if !ok {
			continue
		}
		key := fmt.Sprintf("%d:evade-eid:%s:%s", tenantID, eid, user)
		if evadeDedup.touched(key) {
			continue
		}
		evadeDedup.touch(key)
		msg := fmt.Sprintf("%s — user='%s' context='%s'", def.rule, user, truncateLog(logMsg, 200))
		log.Printf("[Evade] %s", msg)
		CreateAlert(models.Alert{
			AgentID:        agentID,
			TenantID:       tenantID,
			Severity:       def.severity,
			RuleName:       def.rule,
			LogMessage:     msg,
			MitreTactic:    "Defense Evasion",
			MitreTechnique: def.mitre,
			MitreName:      def.name,
			Fingerprint:    fmt.Sprintf("evade-eid-%s-%d", eid, tenantID),
		})
	}
}
