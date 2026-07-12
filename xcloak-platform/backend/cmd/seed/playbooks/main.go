// Seed prebuilt SOAR playbooks for a tenant.
//
// Usage (dev):
//
//	cd xcloak-platform/backend && go run ./cmd/seed/playbooks
//
// Override tenant via SEED_TENANT_ID env var (default 1).
package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"
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

var prebuilt = []prebuiltPB{
	{
		name: "Ransomware: Full Containment Response", triggerType: "alert_critical", actionType: "isolate_host",
		steps: []pbStep{
			{1, "isolate_host", `{}`, ``, "isolate"},
			{2, "collect_processes", `{}`, ``, "snapshot_procs"},
			{3, "collect_file_hashes", `{}`, ``, "snapshot_hashes"},
			{4, "pagerduty_incident", `{"severity":"critical","component":"endpoint","summary":"Ransomware containment initiated"}`, ``, "page_oncall"},
		},
	},
	{
		name: "C2 Beacon: Block and Collect", triggerType: "alert_high", actionType: "collect_connections",
		steps: []pbStep{
			{1, "collect_connections", `{}`, ``, "collect_net"},
			{2, "collect_processes", `{}`, ``, "collect_procs"},
			{3, "webhook", `{"url":"{{SIEM_WEBHOOK}}","method":"POST","body":{"event":"c2_beacon","agent":"{{alert.agent_id}}"}}`, ``, "alert_siem"},
			{4, "slack_message", `{"channel":"#soc-alerts","text":"C2 beacon detected on {{alert.hostname}} — connections collected, review dashboard."}`, ``, "notify_slack"},
		},
	},
	{
		name: "YARA Malware Match: Quarantine and DFIR", triggerType: "YARA Match", actionType: "quarantine_file",
		steps: []pbStep{
			{1, "quarantine_file", `{"path":"{{alert.file_path}}"}`, ``, "quarantine"},
			{2, "collect_file_hashes", `{}`, ``, "hash_scan"},
			{3, "collect_processes", `{}`, ``, "proc_snap"},
			{4, "pagerduty_incident", `{"severity":"high","component":"malware","summary":"YARA match quarantine — {{alert.rule_name}}"}`, ``, "page_soc"},
		},
	},
	{
		name: "Brute Force: Block and Alert", triggerType: "alert_high", actionType: "webhook",
		steps: []pbStep{
			{1, "webhook", `{"url":"{{FIREWALL_API}}","method":"POST","body":{"action":"block","ip":"{{alert.src_ip}}"}}`, ``, "block_ip"},
			{2, "slack_message", `{"channel":"#soc-alerts","text":"Brute-force source {{alert.src_ip}} blocked via firewall."}`, ``, "notify"},
			{3, "collect_auth_logs", `{}`, ``, "collect_auth"},
		},
	},
	{
		name: "Data Exfiltration: Isolate and Notify", triggerType: "alert_critical", actionType: "isolate_host",
		steps: []pbStep{
			{1, "collect_connections", `{}`, ``, "capture_net"},
			{2, "isolate_host", `{}`, ``, "isolate"},
			{3, "email_alert", `{"to":"ciso@company.com","subject":"Exfiltration alert — host isolated","body":"Agent {{alert.hostname}} isolated after exfiltration detection."}`, ``, "email_ciso"},
			{4, "pagerduty_incident", `{"severity":"critical","component":"data-loss","summary":"Potential exfiltration — host isolated"}`, ``, "page_oncall"},
		},
	},
	{
		name: "IOC Match: Enrich and Block", triggerType: "IOC Match", actionType: "webhook",
		steps: []pbStep{
			{1, "collect_connections", `{}`, ``, "capture"},
			{2, "webhook", `{"url":"{{FIREWALL_API}}","method":"POST","body":{"action":"block","ip":"{{alert.ioc_value}}"}}`, ``, "block"},
			{3, "slack_message", `{"channel":"#threat-intel","text":"IOC match on {{alert.hostname}}: {{alert.ioc_value}} blocked."}`, ``, "notify"},
		},
	},
	{
		name: "Privilege Escalation: Collect and Page", triggerType: "alert_high", actionType: "collect_processes",
		steps: []pbStep{
			{1, "collect_processes", `{}`, ``, "proc_snap"},
			{2, "collect_users", `{}`, ``, "user_snap"},
			{3, "collect_auth_logs", `{}`, ``, "auth_snap"},
			{4, "pagerduty_incident", `{"severity":"high","component":"identity","summary":"Privilege escalation detected — {{alert.hostname}}"}`, ``, "page"},
		},
	},
	{
		name: "Lateral Movement: Isolate Source Host", triggerType: "alert_critical", actionType: "isolate_host",
		steps: []pbStep{
			{1, "collect_connections", `{}`, ``, "net_snap"},
			{2, "collect_processes", `{}`, ``, "proc_snap"},
			{3, "isolate_host", `{}`, `severity == "critical"`, "isolate"},
			{4, "slack_message", `{"channel":"#soc-critical","text":"Lateral movement on {{alert.hostname}} — host isolated."}`, ``, "notify"},
		},
	},
	{
		name: "Port Scan: Firewall Block and Log", triggerType: "alert_medium", actionType: "webhook",
		steps: []pbStep{
			{1, "collect_connections", `{}`, ``, "capture_net"},
			{2, "webhook", `{"url":"{{FIREWALL_API}}","method":"POST","body":{"action":"rate_limit","ip":"{{alert.src_ip}}"}}`, ``, "rate_limit"},
			{3, "slack_message", `{"channel":"#soc-alerts","text":"Port scan from {{alert.src_ip}} — rate-limited at firewall."}`, ``, "notify"},
		},
	},
	{
		name: "Insider Threat: Snapshot and Escalate", triggerType: "alert_high", actionType: "collect_processes",
		steps: []pbStep{
			{1, "collect_processes", `{}`, ``, "proc_snap"},
			{2, "collect_connections", `{}`, ``, "net_snap"},
			{3, "collect_auth_logs", `{}`, ``, "auth_snap"},
			{4, "email_alert", `{"to":"hr-security@company.com","subject":"Insider threat alert","body":"User activity on {{alert.hostname}} flagged. Evidence collected."}`, ``, "email_hr"},
		},
	},
	{
		name: "Phishing Response: Quarantine and Notify", triggerType: "alert_medium", actionType: "quarantine_file",
		steps: []pbStep{
			{1, "quarantine_file", `{"path":"{{alert.file_path}}"}`, ``, "quarantine"},
			{2, "email_alert", `{"to":"security@company.com","subject":"Phishing attachment quarantined","body":"File quarantined on {{alert.hostname}}."}`, ``, "notify_user"},
			{3, "slack_message", `{"channel":"#soc-alerts","text":"Phishing file quarantined on {{alert.hostname}} — rule: {{alert.rule_name}}"}`, ``, "notify_soc"},
		},
	},
	{
		name: "Supply Chain: Full Audit Snapshot", triggerType: "alert_critical", actionType: "collect_packages",
		steps: []pbStep{
			{1, "collect_packages", `{}`, ``, "pkg_snap"},
			{2, "collect_file_hashes", `{}`, ``, "hash_snap"},
			{3, "collect_processes", `{}`, ``, "proc_snap"},
			{4, "pagerduty_incident", `{"severity":"critical","component":"supply-chain","summary":"Supply chain compromise suspected on {{alert.hostname}}"}`, ``, "page"},
		},
	},
	{
		name: "Critical Incident: Auto-DFIR Collection", triggerType: "incident_created", actionType: "collect_processes",
		steps: []pbStep{
			{1, "collect_processes", `{}`, ``, "proc_snap"},
			{2, "collect_connections", `{}`, ``, "net_snap"},
			{3, "collect_file_hashes", `{}`, ``, "hash_snap"},
			{4, "collect_auth_logs", `{}`, ``, "auth_snap"},
			{5, "slack_message", `{"channel":"#soc-incidents","text":"Auto-DFIR snapshot collected for new incident #{{incident.id}}."}`, ``, "notify"},
		},
	},
	{
		name: "Zero-Day Exploit: Emergency Isolation", triggerType: "alert_critical", actionType: "isolate_host",
		steps: []pbStep{
			{1, "isolate_host", `{}`, ``, "isolate"},
			{2, "collect_processes", `{}`, ``, "proc_snap"},
			{3, "collect_connections", `{}`, ``, "net_snap"},
			{4, "collect_file_hashes", `{}`, ``, "hash_snap"},
			{5, "pagerduty_incident", `{"severity":"critical","component":"zero-day","summary":"Zero-day exploit suspected — {{alert.hostname}} isolated"}`, ``, "page_ciso"},
			{6, "email_alert", `{"to":"ciso@company.com","subject":"[CRITICAL] Zero-day response initiated","body":"Host {{alert.hostname}} isolated. DFIR snapshot underway."}`, ``, "email_ciso"},
		},
	},
}

func main() {
	godotenv.Load()

	tenantID := 1
	if v := os.Getenv("SEED_TENANT_ID"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			tenantID = n
		}
	}

	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		env("DB_HOST", "127.0.0.1"),
		env("DB_PORT", "5432"),
		env("DB_USER", "xcloak"),
		env("DB_PASSWORD", "xcloak"),
		env("DB_NAME", "ngfw"),
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		log.Fatalf("cannot reach database: %v", err)
	}

	log.Printf("Seeding 14 prebuilt playbooks for tenant_id=%d…", tenantID)

	// Fetch existing agent IDs for this tenant (for sample executions)
	rows, _ := db.Query(`SELECT id FROM agents WHERE tenant_id=$1 LIMIT 4`, tenantID)
	var agentIDs []int
	if rows != nil {
		for rows.Next() {
			var id int
			if err := rows.Scan(&id); err == nil {
				agentIDs = append(agentIDs, id)
			}
		}
		rows.Close()
	}

	var pbIDs []int
	for _, p := range prebuilt {
		var id int
		err := db.QueryRow(`
			INSERT INTO playbooks (name, trigger_type, action_type, enabled, tenant_id)
			VALUES ($1,$2,$3,true,$4)
			ON CONFLICT DO NOTHING
			RETURNING id`,
			p.name, p.triggerType, p.actionType, tenantID,
		).Scan(&id)
		if err != nil {
			// Already exists or other error — skip
			continue
		}
		pbIDs = append(pbIDs, id)
		log.Printf("  + playbook %d: %s", id, p.name)

		for _, s := range p.steps {
			payload := s.payload
			if payload == "" {
				payload = "{}"
			}
			if _, aerr := db.Exec(`
				INSERT INTO playbook_actions
					(playbook_id, step_order, action_type, payload, condition_expr,
					 max_retries, retry_delay_secs, timeout_seconds, run_parallel,
					 step_name, tenant_id)
				VALUES ($1,$2,$3,$4::jsonb,$5,0,5,60,false,$6,$7)`,
				id, s.stepOrder, s.actionType, payload, s.condition, s.stepName, tenantID,
			); aerr != nil {
				log.Printf("    action step %d: %v", s.stepOrder, aerr)
			}
		}
	}

	// Seed a few pending-approval executions if we have agents + playbooks
	if len(pbIDs) >= 3 && len(agentIDs) >= 1 {
		aID := agentIDs[0]
		execs := []struct {
			pbIdx  int
			action string
			ago    time.Duration
		}{
			{0, "isolate_host", 10 * time.Minute},
			{2, "quarantine_file", 5 * time.Minute},
			{7, "isolate_host", 2 * time.Minute},
		}
		for _, ex := range execs {
			if ex.pbIdx >= len(pbIDs) {
				continue
			}
			if _, err := db.Exec(`
				INSERT INTO playbook_executions
					(playbook_id, agent_id, action_type, status, created_at, tenant_id)
				VALUES ($1,$2,$3,'pending_approval',$4,$5)`,
				pbIDs[ex.pbIdx], aID, ex.action, time.Now().Add(-ex.ago), tenantID,
			); err != nil {
				log.Printf("  exec insert: %v", err)
			}
		}
		log.Printf("  + 3 pending-approval executions seeded")
	}

	log.Printf("Done — %d playbooks inserted.", len(pbIDs))
}
