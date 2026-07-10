package services

import (
	"strings"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// MapMITRE enriches an alert with MITRE ATT&CK data.
// Priority: 1) DB lookup by exact rule name, 2) keyword heuristic fallback.
func MapMITRE(alert *models.Alert) {

	// Try DB first.
	var tactic, technique, name string

	err := database.DB.QueryRow(`
		SELECT tactic, technique, name
		FROM mitre_mappings
		WHERE LOWER(rule_name) = LOWER($1)
	`, alert.RuleName).Scan(&tactic, &technique, &name)

	if err == nil {
		alert.MitreTactic    = tactic
		alert.MitreTechnique = technique
		alert.MitreName      = name
		return
	}

	// Fallback: keyword-based heuristic so unknown rules aren't labeled "Unknown".
	msg := strings.ToLower(alert.RuleName + " " + alert.LogMessage)

	switch {
	case contains(msg, "brute", "failed password", "invalid user", "authentication failure"):
		alert.MitreTactic, alert.MitreTechnique, alert.MitreName =
			"Credential Access", "T1110", "Brute Force"

	case contains(msg, "ssh", "login", "accepted password", "session opened"):
		alert.MitreTactic, alert.MitreTechnique, alert.MitreName =
			"Initial Access", "T1078", "Valid Accounts"

	case contains(msg, "sudo", "privilege", "escalat"):
		alert.MitreTactic, alert.MitreTechnique, alert.MitreName =
			"Privilege Escalation", "T1548", "Abuse Elevation Control"

	case contains(msg, "useradd", "adduser", "new user", "account creat"):
		alert.MitreTactic, alert.MitreTechnique, alert.MitreName =
			"Persistence", "T1136", "Create Account"

	case contains(msg, "cron", "crontab", "at ", "scheduled"):
		alert.MitreTactic, alert.MitreTechnique, alert.MitreName =
			"Persistence", "T1053", "Scheduled Task/Job"

	case contains(msg, "base64", "decode", "obfuscat"):
		alert.MitreTactic, alert.MitreTechnique, alert.MitreName =
			"Defense Evasion", "T1140", "Deobfuscate/Decode Files"

	case contains(msg, "reverse shell", "/dev/tcp", "bash -i", "nc -e"):
		alert.MitreTactic, alert.MitreTechnique, alert.MitreName =
			"Execution", "T1059", "Command and Scripting Interpreter"

	case contains(msg, "ioc", "indicator", "blacklist", "threat feed"):
		alert.MitreTactic, alert.MitreTechnique, alert.MitreName =
			"Command and Control", "T1071", "Application Layer Protocol"

	case contains(msg, "yara", "malware", "trojan", "virus"):
		alert.MitreTactic, alert.MitreTechnique, alert.MitreName =
			"Defense Evasion", "T1027", "Obfuscated Files or Information"

	case contains(msg, "scan", "nmap", "masscan", "port"):
		alert.MitreTactic, alert.MitreTechnique, alert.MitreName =
			"Discovery", "T1046", "Network Service Discovery"

	case contains(msg, "chmod", "chown", "permission", "/etc"):
		alert.MitreTactic, alert.MitreTechnique, alert.MitreName =
			"Persistence", "T1222", "File and Directory Permissions"

	case contains(msg, "wget", "curl", "download", "fetch"):
		alert.MitreTactic, alert.MitreTechnique, alert.MitreName =
			"Command and Control", "T1105", "Ingress Tool Transfer"

	case contains(msg, "cve", "exploit", "vulnerab"):
		alert.MitreTactic, alert.MitreTechnique, alert.MitreName =
			"Execution", "T1203", "Exploitation for Client Execution"

	case contains(msg, "dns", "domain", "resolv"):
		alert.MitreTactic, alert.MitreTechnique, alert.MitreName =
			"Command and Control", "T1071", "Application Layer Protocol"

	default:
		alert.MitreTactic    = "Unknown"
		alert.MitreTechnique = "T0000"
		alert.MitreName      = "Uncategorized"
	}
}

func contains(s string, terms ...string) bool {
	for _, t := range terms {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}

// GetMITREMappings returns all configured mappings for the UI.
func GetMITREMappings() ([]map[string]string, error) {

	rows, err := database.DB.Query(`
		SELECT rule_name, tactic, technique, name
		FROM mitre_mappings ORDER BY tactic, technique
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []map[string]string
	for rows.Next() {
		var ruleName, tactic, technique, name string
		if err := rows.Scan(&ruleName, &tactic, &technique, &name); err == nil {
			out = append(out, map[string]string{
				"rule_name": ruleName, "tactic": tactic,
				"technique": technique, "name": name,
			})
		}
	}
	return out, nil
}
