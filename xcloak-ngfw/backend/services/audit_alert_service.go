package services

import (
	"fmt"
	"strings"

	"xcloak-ngfw/models"
)

// threatTagToMITRE maps classifier tags to MITRE ATT&CK tactic/technique pairs.
var threatTagToMITRE = map[string][3]string{
	"reverse_shell":      {"Execution",            "T1059.004", "Unix Shell"},
	"obfuscated_exec":    {"Defense Evasion",       "T1140",     "Deobfuscate/Decode"},
	"powershell_encoded": {"Execution",             "T1059.001", "PowerShell"},
	"powershell_download":{"Command and Control",   "T1105",     "Ingress Tool Transfer"},
	"python_exec":        {"Execution",             "T1059.006", "Python"},
	"python_reverse_shell":{"Execution",            "T1059.006", "Python"},
	"script_exec":        {"Execution",             "T1059",     "Command Scripting"},
	"log_tampering":      {"Defense Evasion",       "T1070",     "Indicator Removal"},
	"defense_disabled":   {"Defense Evasion",       "T1562",     "Impair Defenses"},
	"sudo_shell":         {"Privilege Escalation",  "T1548.003", "Sudo and Sudo Caching"},
	"setuid_set":         {"Privilege Escalation",  "T1548.001", "Setuid and Setgid"},
	"container_escape":   {"Privilege Escalation",  "T1611",     "Escape to Host"},
	"cron_persistence":   {"Persistence",           "T1053.003", "Cron"},
	"ssh_key_added":      {"Persistence",           "T1098",     "Account Manipulation"},
	"service_persistence":{"Persistence",           "T1543.002", "Systemd Service"},
	"credential_dump":    {"Credential Access",     "T1003.008", "/etc/passwd and /etc/shadow"},
	"credential_search":  {"Credential Access",     "T1552",     "Unsecured Credentials"},
	"network_scan":       {"Discovery",             "T1046",     "Network Service Discovery"},
	"host_discovery":     {"Discovery",             "T1018",     "Remote System Discovery"},
	"network_enum":       {"Discovery",             "T1049",     "System Network Connections"},
	"ssh_lateral_move":   {"Lateral Movement",      "T1021.004", "SSH"},
	"tunnel_tool":        {"Command and Control",   "T1219",     "Remote Access Software"},
	"dropper":            {"Execution",             "T1105",     "Ingress Tool Transfer"},
	"data_exfil":         {"Exfiltration",          "T1048",     "Exfiltration Over Alt Protocol"},
}

// threatTagToSeverity maps classifier tags to alert severities.
var threatTagToSeverity = map[string]string{
	"reverse_shell":       "critical",
	"python_reverse_shell":"critical",
	"container_escape":    "critical",
	"defense_disabled":    "critical",
	"obfuscated_exec":     "high",
	"powershell_encoded":  "high",
	"powershell_download": "high",
	"log_tampering":       "high",
	"sudo_shell":          "high",
	"credential_dump":     "high",
	"data_exfil":          "high",
	"dropper":             "high",
	"ssh_key_added":       "high",
	"service_persistence": "high",
	"ssh_lateral_move":    "high",
	"python_exec":         "medium",
	"script_exec":         "medium",
	"setuid_set":          "medium",
	"cron_persistence":    "medium",
	"credential_search":   "medium",
	"tunnel_tool":         "medium",
	"network_scan":        "medium",
	"host_discovery":      "low",
	"network_enum":        "low",
}

// CreateAlertFromAuditEvent fires an alert when a threat-tagged audit event
// arrives. It maps the classifier tag to a MITRE technique and creates an
// alert that feeds the existing correlation and SOAR pipeline.
func CreateAlertFromAuditEvent(ev models.AuditEvent) {
	if ev.ThreatTag == "" {
		return
	}

	mitre := threatTagToMITRE[ev.ThreatTag]
	sev   := threatTagToSeverity[ev.ThreatTag]
	if sev == "" {
		sev = "medium"
	}

	// Build a readable rule name from the tag.
	ruleName := strings.ReplaceAll(strings.Title(strings.ReplaceAll(ev.ThreatTag, "_", " ")), " ", " ")

	// Cap cmdline to 300 chars for the alert message.
	cmdline := ev.Cmdline
	if len(cmdline) > 300 {
		cmdline = cmdline[:300] + "…"
	}

	logMsg := fmt.Sprintf(
		"[auditd] pid=%d user=%s exe=%s cmd=%s",
		ev.PID, ev.Username, ev.Exe, cmdline,
	)

	fingerprint := fmt.Sprintf("audit-%d-%s-%d", ev.AgentID, ev.ThreatTag, ev.PID)

	alert := models.Alert{
		AgentID:        ev.AgentID,
		Severity:       sev,
		RuleName:       ruleName,
		LogMessage:     logMsg,
		MitreTactic:    mitre[0],
		MitreTechnique: mitre[1],
		MitreName:      mitre[2],
		Fingerprint:    fingerprint,
	}

	CreateAlert(alert)
	CorrelateAlert(alert)
}

// CreateAlertFromRegistryEntry fires an alert for suspicious registry entries.
func CreateAlertFromRegistryEntry(e models.RegistryEntry) {

	tagToMITRE := map[string][3]string{
		"run_key_suspicious":   {"Persistence", "T1547.001", "Registry Run Keys / Startup Folder"},
		"ifeo_hijack":          {"Privilege Escalation", "T1546.012", "Image File Execution Options Injection"},
		"appinit_dll":          {"Privilege Escalation", "T1546.010", "AppInit DLLs"},
		"winlogon_hijack":      {"Persistence", "T1547.004", "Winlogon Helper DLL"},
		"boot_execute_tamper":  {"Persistence", "T1547.001", "Registry Run Keys / Startup Folder"},
	}
	tagToSeverity := map[string]string{
		"run_key_suspicious":   "high",
		"ifeo_hijack":          "critical",
		"appinit_dll":          "critical",
		"winlogon_hijack":      "critical",
		"boot_execute_tamper":  "high",
	}

	mitre := tagToMITRE[e.ThreatTag]
	sev   := tagToSeverity[e.ThreatTag]
	if sev == "" {
		return
	}

	ruleName := strings.Title(strings.ReplaceAll(e.ThreatTag, "_", " "))
	logMsg   := fmt.Sprintf("[registry] %s\\%s\\%s = %s", e.Hive, e.KeyPath, e.Name, e.Data)
	fp       := fmt.Sprintf("registry-%d-%s-%s", e.AgentID, e.ThreatTag, e.Name)

	alert := models.Alert{
		AgentID:        e.AgentID,
		Severity:       sev,
		RuleName:       ruleName,
		LogMessage:     logMsg,
		MitreTactic:    mitre[0],
		MitreTechnique: mitre[1],
		MitreName:      mitre[2],
		Fingerprint:    fp,
	}
	CreateAlert(alert)
	CorrelateAlert(alert)
}
