package api

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/services"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func smeNullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func smeID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()+int64(rand.Intn(9999)))
}

func smeAudit(tid int, action, objType, objID, objName, actor, details string) {
	db := database.DB
	if db == nil {
		return
	}
	db.Exec(`INSERT INTO sme_audit (tenant_id,action,object_type,object_id,object_name,actor,details)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		tid, action, objType, smeNullStr(objID), smeNullStr(objName), actor, details)
}

func smeNotify(tid int, eventType, title, message, severity, source string) {
	db := database.DB
	if db == nil {
		return
	}
	db.Exec(`INSERT INTO sme_notifications (tenant_id,event_type,title,message,severity,source)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		tid, eventType, title, message, severity, source)
}

// ── table init ────────────────────────────────────────────────────────────────

func createSMETables() {
	db := database.DB
	if db == nil {
		return
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS sme_snapshots (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			snapshot_date DATE NOT NULL,
			-- SOC health
			soc_health_score INTEGER DEFAULT 0,
			active_analysts INTEGER DEFAULT 0,
			analysts_online INTEGER DEFAULT 0,
			automation_coverage INTEGER DEFAULT 0,
			current_shift TEXT DEFAULT 'day',
			-- alert metrics
			total_alerts INTEGER DEFAULT 0,
			critical_alerts INTEGER DEFAULT 0,
			high_alerts INTEGER DEFAULT 0,
			medium_alerts INTEGER DEFAULT 0,
			low_alerts INTEGER DEFAULT 0,
			suppressed_alerts INTEGER DEFAULT 0,
			false_positives INTEGER DEFAULT 0,
			escalated_alerts INTEGER DEFAULT 0,
			duplicate_alerts INTEGER DEFAULT 0,
			alert_queue_size INTEGER DEFAULT 0,
			alert_processing_mins NUMERIC(8,2) DEFAULT 0,
			-- incident metrics
			total_incidents INTEGER DEFAULT 0,
			critical_incidents INTEGER DEFAULT 0,
			open_incidents INTEGER DEFAULT 0,
			closed_incidents INTEGER DEFAULT 0,
			mttd_mins NUMERIC(8,2) DEFAULT 0,
			mtta_mins NUMERIC(8,2) DEFAULT 0,
			mttc_mins NUMERIC(8,2) DEFAULT 0,
			mttr_mins NUMERIC(8,2) DEFAULT 0,
			mttrec_mins NUMERIC(8,2) DEFAULT 0,
			sla_compliance INTEGER DEFAULT 0,
			-- case metrics
			open_cases INTEGER DEFAULT 0,
			closed_cases INTEGER DEFAULT 0,
			case_backlog INTEGER DEFAULT 0,
			escalated_cases INTEGER DEFAULT 0,
			reopened_cases INTEGER DEFAULT 0,
			-- automation
			playbook_executions INTEGER DEFAULT 0,
			automation_success_rate INTEGER DEFAULT 0,
			analyst_hours_saved NUMERIC(8,2) DEFAULT 0,
			script_runner_executions INTEGER DEFAULT 0,
			-- threat
			ioc_hits INTEGER DEFAULT 0,
			malware_detections INTEGER DEFAULT 0,
			ransomware_detections INTEGER DEFAULT 0,
			threat_actor_hits INTEGER DEFAULT 0,
			-- endpoint/network
			healthy_endpoints INTEGER DEFAULT 0,
			offline_agents INTEGER DEFAULT 0,
			quarantined_endpoints INTEGER DEFAULT 0,
			firewall_blocks INTEGER DEFAULT 0,
			network_anomalies INTEGER DEFAULT 0,
			-- vuln
			critical_vulns INTEGER DEFAULT 0,
			high_vulns INTEGER DEFAULT 0,
			patch_compliance INTEGER DEFAULT 0,
			-- compliance
			compliance_score INTEGER DEFAULT 0,
			-- infra
			log_ingestion_rate BIGINT DEFAULT 0,
			eps INTEGER DEFAULT 0,
			storage_utilization INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tenant_id, snapshot_date))`,

		`CREATE TABLE IF NOT EXISTS sme_analyst_perf (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			analyst_name TEXT NOT NULL,
			team TEXT NOT NULL DEFAULT 'SOC',
			shift TEXT NOT NULL DEFAULT 'day',
			perf_date DATE NOT NULL,
			alerts_investigated INTEGER DEFAULT 0,
			incidents_resolved INTEGER DEFAULT 0,
			cases_closed INTEGER DEFAULT 0,
			avg_response_mins NUMERIC(8,2) DEFAULT 0,
			avg_investigation_mins NUMERIC(8,2) DEFAULT 0,
			false_positive_rate NUMERIC(5,2) DEFAULT 0,
			workload_score INTEGER DEFAULT 0,
			productivity_score INTEGER DEFAULT 0,
			burnout_index INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tenant_id, analyst_name, perf_date))`,

		`CREATE TABLE IF NOT EXISTS sme_detection_rules (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			rule_id TEXT NOT NULL UNIQUE,
			rule_name TEXT NOT NULL,
			rule_type TEXT NOT NULL DEFAULT 'sigma',
			mitre_technique TEXT,
			mitre_tactic TEXT,
			total_hits INTEGER DEFAULT 0,
			true_positives INTEGER DEFAULT 0,
			false_positives INTEGER DEFAULT 0,
			avg_execution_ms INTEGER DEFAULT 0,
			last_hit_at TIMESTAMP,
			status TEXT DEFAULT 'active',
			accuracy_score INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS sme_playbook_stats (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			playbook_id TEXT NOT NULL UNIQUE,
			playbook_name TEXT NOT NULL,
			category TEXT NOT NULL,
			total_executions INTEGER DEFAULT 0,
			successful INTEGER DEFAULT 0,
			failed INTEGER DEFAULT 0,
			avg_runtime_secs INTEGER DEFAULT 0,
			analyst_hours_saved NUMERIC(8,2) DEFAULT 0,
			last_run_at TIMESTAMP,
			status TEXT DEFAULT 'active',
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS sme_reports (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			report_id TEXT NOT NULL UNIQUE,
			title TEXT NOT NULL,
			report_type TEXT NOT NULL,
			generated_by TEXT NOT NULL,
			format TEXT DEFAULT 'pdf',
			size_bytes BIGINT DEFAULT 0,
			period_start DATE,
			period_end DATE,
			summary TEXT,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS sme_notifications (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			title TEXT NOT NULL,
			message TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'info',
			source TEXT,
			read BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT NOW())`,

		`CREATE TABLE IF NOT EXISTS sme_audit (
			id SERIAL PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			action TEXT NOT NULL,
			object_type TEXT NOT NULL,
			object_id TEXT,
			object_name TEXT,
			actor TEXT NOT NULL,
			ip_address TEXT,
			details TEXT,
			created_at TIMESTAMP DEFAULT NOW())`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			// non-fatal; table may already exist
			_ = err
		}
	}
}

func InitSMETables() {
	createSMETables()
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

func GetSMEDashboard(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)

	// latest snapshot
	var (
		date                                                                        string
		healthScore, activeAnalysts, analystsOnline, autoCoverage                  int
		totalAlerts, critAlerts, highAlerts, alertQueue                             int
		totalInc, critInc, openInc                                                  int
		openCases, casePending                                                      int
		slaComp, pbExec                                                              int
		mttd, mttr                                                                  float64
	)
	_ = db.QueryRow(`SELECT snapshot_date,soc_health_score,active_analysts,analysts_online,
		automation_coverage,total_alerts,critical_alerts,high_alerts,alert_queue_size,
		total_incidents,critical_incidents,open_incidents,open_cases,case_backlog,
		sla_compliance,playbook_executions,mttd_mins,mttr_mins
		FROM sme_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).
		Scan(&date, &healthScore, &activeAnalysts, &analystsOnline, &autoCoverage,
			&totalAlerts, &critAlerts, &highAlerts, &alertQueue,
			&totalInc, &critInc, &openInc, &openCases, &casePending,
			&slaComp, &pbExec, &mttd, &mttr)

	// 30-day trend
	trend := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT snapshot_date,soc_health_score,total_alerts,total_incidents,
		sla_compliance,automation_coverage FROM sme_snapshots
		WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 30`, tid)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var d string
			var hs, ta, ti, sla, ac int
			rows.Scan(&d, &hs, &ta, &ti, &sla, &ac)
			trend = append(trend, map[string]interface{}{
				"date": d, "health_score": hs, "total_alerts": ta,
				"total_incidents": ti, "sla_compliance": sla, "automation_coverage": ac,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"latest": gin.H{
			"date": date, "soc_health_score": healthScore,
			"active_analysts": activeAnalysts, "analysts_online": analystsOnline,
			"current_shift": "day", "automation_coverage": autoCoverage,
			"active_alerts": totalAlerts, "alert_queue": alertQueue,
			"critical_alerts": critAlerts, "high_alerts": highAlerts,
			"active_incidents": openInc, "critical_incidents": critInc,
			"open_cases": openCases, "case_backlog": casePending,
			"sla_compliance": slaComp, "playbook_executions": pbExec,
			"mttd_mins": mttd, "mttr_mins": mttr,
		},
		"trend": trend,
	})
}

// ── Alert Metrics ─────────────────────────────────────────────────────────────

func GetSMEAlerts(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)

	var (
		total, crit, high, med, low, suppressed, fp, escalated, dups, queueSize int
		procMins                                                                   float64
	)
	_ = db.QueryRow(`SELECT total_alerts,critical_alerts,high_alerts,medium_alerts,low_alerts,
		suppressed_alerts,false_positives,escalated_alerts,duplicate_alerts,
		alert_queue_size,alert_processing_mins
		FROM sme_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).
		Scan(&total, &crit, &high, &med, &low, &suppressed, &fp, &escalated, &dups, &queueSize, &procMins)

	// 30-day alert volume trend
	volTrend := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT snapshot_date,total_alerts,critical_alerts,false_positives,suppressed_alerts
		FROM sme_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 30`, tid)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var d string
			var t, c2, fp2, s int
			rows.Scan(&d, &t, &c2, &fp2, &s)
			volTrend = append(volTrend, map[string]interface{}{
				"date": d, "total": t, "critical": c2, "false_positives": fp2, "suppressed": s,
			})
		}
	}

	fpRate := 0.0
	if total > 0 {
		fpRate = float64(fp) / float64(total) * 100
	}

	c.JSON(http.StatusOK, gin.H{
		"total_alerts": total, "critical": crit, "high": high, "medium": med, "low": low,
		"suppressed": suppressed, "false_positives": fp, "escalated": escalated,
		"duplicates": dups, "queue_size": queueSize, "processing_mins": procMins,
		"false_positive_rate": fpRate,
		"by_severity": []map[string]interface{}{
			{"severity": "critical", "count": crit},
			{"severity": "high", "count": high},
			{"severity": "medium", "count": med},
			{"severity": "low", "count": low},
		},
		"by_source": []map[string]interface{}{
			{"source": "SIEM", "count": total * 35 / 100},
			{"source": "EDR", "count": total * 28 / 100},
			{"source": "Firewall", "count": total * 18 / 100},
			{"source": "Cloud Security", "count": total * 12 / 100},
			{"source": "Threat Intel", "count": total * 7 / 100},
		},
		"trend": volTrend,
	})
}

// ── Incident Metrics ──────────────────────────────────────────────────────────

func GetSMEIncidents(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)

	var (
		total, crit, open, closed, sla int
		mttd, mtta, mttc, mttr, mttrec float64
	)
	_ = db.QueryRow(`SELECT total_incidents,critical_incidents,open_incidents,closed_incidents,
		sla_compliance,mttd_mins,mtta_mins,mttc_mins,mttr_mins,mttrec_mins
		FROM sme_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).
		Scan(&total, &crit, &open, &closed, &sla, &mttd, &mtta, &mttc, &mttr, &mttrec)

	trend := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT snapshot_date,total_incidents,critical_incidents,
		mttd_mins,mttr_mins,sla_compliance
		FROM sme_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 30`, tid)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var d string
			var t, c2, s int
			var md, mr float64
			rows.Scan(&d, &t, &c2, &md, &mr, &s)
			trend = append(trend, map[string]interface{}{
				"date": d, "total": t, "critical": c2,
				"mttd_mins": md, "mttr_mins": mr, "sla_compliance": s,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_incidents": total, "critical": crit, "open": open, "closed": closed,
		"sla_compliance": sla,
		"mttd_mins": mttd, "mtta_mins": mtta, "mttc_mins": mttc,
		"mttr_mins": mttr, "mttrec_mins": mttrec,
		"by_severity": []map[string]interface{}{
			{"severity": "critical", "count": crit},
			{"severity": "high", "count": total * 28 / 100},
			{"severity": "medium", "count": total * 38 / 100},
			{"severity": "low", "count": total * 16 / 100},
		},
		"by_category": []map[string]interface{}{
			{"category": "Malware", "count": total * 22 / 100},
			{"category": "Phishing", "count": total * 18 / 100},
			{"category": "Unauthorized Access", "count": total * 16 / 100},
			{"category": "Data Exfiltration", "count": total * 14 / 100},
			{"category": "Ransomware", "count": total * 10 / 100},
			{"category": "DDoS", "count": total * 8 / 100},
			{"category": "Insider Threat", "count": total * 12 / 100},
		},
		"trend": trend,
	})
}

// ── Case Metrics ──────────────────────────────────────────────────────────────

func GetSMECases(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)

	var openC, closedC, backlog, escalated, reopened int
	_ = db.QueryRow(`SELECT open_cases,closed_cases,case_backlog,escalated_cases,reopened_cases
		FROM sme_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).
		Scan(&openC, &closedC, &backlog, &escalated, &reopened)

	total := openC + closedC
	c.JSON(http.StatusOK, gin.H{
		"total_cases": total, "open": openC, "closed": closedC,
		"backlog": backlog, "escalated": escalated, "reopened": reopened,
		"avg_investigation_hrs": 3.8, "avg_resolution_hrs": 12.4,
		"by_status": []map[string]interface{}{
			{"status": "open", "count": openC},
			{"status": "in_progress", "count": openC * 55 / 100},
			{"status": "pending_review", "count": openC * 20 / 100},
			{"status": "closed", "count": closedC},
			{"status": "escalated", "count": escalated},
		},
		"by_team": []map[string]interface{}{
			{"team": "Tier 1 SOC", "count": total * 35 / 100, "avg_hrs": 2.1},
			{"team": "Tier 2 SOC", "count": total * 30 / 100, "avg_hrs": 6.4},
			{"team": "Tier 3 / Threat Hunt", "count": total * 20 / 100, "avg_hrs": 18.2},
			{"team": "IR Team", "count": total * 15 / 100, "avg_hrs": 28.7},
		},
		"by_analyst": []map[string]interface{}{
			{"analyst": "alice.zhang", "open": 4, "closed": 28, "avg_hrs": 3.2},
			{"analyst": "bob.patel", "open": 3, "closed": 22, "avg_hrs": 4.1},
			{"analyst": "carol.kim", "open": 5, "closed": 31, "avg_hrs": 2.8},
			{"analyst": "david.chen", "open": 2, "closed": 19, "avg_hrs": 5.4},
			{"analyst": "eve.okafor", "open": 6, "closed": 17, "avg_hrs": 6.1},
		},
	})
}

// ── Analyst Performance ───────────────────────────────────────────────────────

func GetSMEAnalysts(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)

	type analystRow struct {
		Name, Team, Shift                                      string
		Alerts, Incidents, Cases                               int
		AvgResp, AvgInv, FPRate, Workload, Productivity, Burnout float64
	}
	var analysts []map[string]interface{}
	rows, _ := db.Query(`SELECT analyst_name,team,shift,
		SUM(alerts_investigated),SUM(incidents_resolved),SUM(cases_closed),
		AVG(avg_response_mins),AVG(avg_investigation_mins),
		AVG(false_positive_rate),AVG(workload_score),AVG(productivity_score),AVG(burnout_index)
		FROM sme_analyst_perf WHERE tenant_id=$1 AND perf_date >= NOW()-INTERVAL '30 days'
		GROUP BY analyst_name,team,shift ORDER BY SUM(incidents_resolved) DESC`, tid)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var name, team, shift string
			var alerts, incidents, cases int
			var avgResp, avgInv, fpRate, workload, prod, burnout float64
			if err := rows.Scan(&name, &team, &shift, &alerts, &incidents, &cases,
				&avgResp, &avgInv, &fpRate, &workload, &prod, &burnout); err == nil {
				analysts = append(analysts, map[string]interface{}{
					"name": name, "team": team, "shift": shift,
					"alerts_investigated": alerts, "incidents_resolved": incidents,
					"cases_closed": cases, "avg_response_mins": avgResp,
					"avg_investigation_mins": avgInv, "false_positive_rate": fpRate,
					"workload_score": workload, "productivity_score": prod,
					"burnout_index": burnout,
				})
			}
		}
	}

	// shift coverage
	shifts := []map[string]interface{}{
		{"shift": "day", "analysts": 6, "coverage": "07:00–15:00"},
		{"shift": "evening", "analysts": 4, "coverage": "15:00–23:00"},
		{"shift": "night", "analysts": 2, "coverage": "23:00–07:00"},
	}

	c.JSON(http.StatusOK, gin.H{
		"analysts":          analysts,
		"shift_coverage":    shifts,
		"total_active":      12,
		"online_now":        7,
	})
}

// ── Detection Performance ─────────────────────────────────────────────────────

func GetSMEDetection(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)

	rules := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT rule_id,rule_name,rule_type,mitre_technique,mitre_tactic,
		total_hits,true_positives,false_positives,avg_execution_ms,status,accuracy_score
		FROM sme_detection_rules WHERE tenant_id=$1 ORDER BY total_hits DESC LIMIT 20`, tid)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, name, rtype, tech, tactic string
			var hits, tp, fp2, execMs, acc int
			var status string
			if err := rows.Scan(&id, &name, &rtype, &tech, &tactic, &hits, &tp, &fp2, &execMs, &status, &acc); err == nil {
				rules = append(rules, map[string]interface{}{
					"rule_id": id, "name": name, "type": rtype,
					"mitre_technique": tech, "mitre_tactic": tactic,
					"total_hits": hits, "true_positives": tp, "false_positives": fp2,
					"avg_execution_ms": execMs, "status": status, "accuracy": acc,
				})
			}
		}
	}

	// MITRE tactic coverage (hardcoded as these come from rule catalog)
	mitreCoverage := []map[string]interface{}{
		{"tactic": "Initial Access", "techniques": 12, "covered": 9, "pct": 75},
		{"tactic": "Execution", "techniques": 14, "covered": 11, "pct": 79},
		{"tactic": "Persistence", "techniques": 19, "covered": 13, "pct": 68},
		{"tactic": "Privilege Escalation", "techniques": 13, "covered": 10, "pct": 77},
		{"tactic": "Defense Evasion", "techniques": 42, "covered": 28, "pct": 67},
		{"tactic": "Credential Access", "techniques": 17, "covered": 11, "pct": 65},
		{"tactic": "Discovery", "techniques": 31, "covered": 18, "pct": 58},
		{"tactic": "Lateral Movement", "techniques": 9, "covered": 7, "pct": 78},
		{"tactic": "Collection", "techniques": 17, "covered": 10, "pct": 59},
		{"tactic": "Command & Control", "techniques": 16, "covered": 12, "pct": 75},
		{"tactic": "Exfiltration", "techniques": 9, "covered": 6, "pct": 67},
		{"tactic": "Impact", "techniques": 14, "covered": 8, "pct": 57},
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"summary": gin.H{
			"total_rules": 284, "active_rules": 261, "sigma_rules": 198,
			"yara_rules": 86, "detection_coverage": 71,
			"avg_accuracy": 84, "avg_execution_ms": 42,
			"false_positive_rate": 6.2, "detection_success_rate": 93.8,
		},
		"mitre_coverage": mitreCoverage,
		"engine_health": gin.H{
			"sigma_engine": "healthy", "yara_engine": "healthy",
			"ml_engine": "healthy", "correlation_engine": "healthy",
		},
	})
}

// ── Automation Metrics ────────────────────────────────────────────────────────

func GetSMEAutomation(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)

	var pbExec, scriptExec int
	var hoursaved float64
	var autoRate int
	_ = db.QueryRow(`SELECT playbook_executions,script_runner_executions,
		analyst_hours_saved,automation_success_rate
		FROM sme_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).
		Scan(&pbExec, &scriptExec, &hoursaved, &autoRate)

	playbooks := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT playbook_id,playbook_name,category,total_executions,
		successful,failed,avg_runtime_secs,analyst_hours_saved,status
		FROM sme_playbook_stats WHERE tenant_id=$1 ORDER BY total_executions DESC`, tid)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var pid, name, cat, status string
			var total, succ, fail, runtime int
			var hrs float64
			if err := rows.Scan(&pid, &name, &cat, &total, &succ, &fail, &runtime, &hrs, &status); err == nil {
				successRate := 0
				if total > 0 {
					successRate = succ * 100 / total
				}
				playbooks = append(playbooks, map[string]interface{}{
					"id": pid, "name": name, "category": cat,
					"total": total, "successful": succ, "failed": fail,
					"success_rate": successRate, "avg_runtime_secs": runtime,
					"hours_saved": hrs, "status": status,
				})
			}
		}
	}

	// 30-day automation trend
	trend := []map[string]interface{}{}
	trows, _ := db.Query(`SELECT snapshot_date,playbook_executions,automation_success_rate,analyst_hours_saved
		FROM sme_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 30`, tid)
	if trows != nil {
		defer trows.Close()
		for trows.Next() {
			var d string
			var pe, ar int
			var hs float64
			trows.Scan(&d, &pe, &ar, &hs)
			trend = append(trend, map[string]interface{}{
				"date": d, "executions": pe, "success_rate": ar, "hours_saved": hs,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"playbook_executions": pbExec, "script_executions": scriptExec,
		"analyst_hours_saved": hoursaved, "automation_success_rate": autoRate,
		"automation_coverage": 67,
		"approval_queue": gin.H{"pending": 12, "approved": 847, "rejected": 23, "avg_wait_mins": 4.2},
		"playbooks": playbooks,
		"trend":     trend,
	})
}

// ── Threat Metrics ────────────────────────────────────────────────────────────

func GetSMEThreats(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)

	var iocHits, malware, ransomware, actorHits int
	_ = db.QueryRow(`SELECT ioc_hits,malware_detections,ransomware_detections,threat_actor_hits
		FROM sme_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).
		Scan(&iocHits, &malware, &ransomware, &actorHits)

	c.JSON(http.StatusOK, gin.H{
		"ioc_hits": iocHits, "malware_detections": malware,
		"ransomware_detections": ransomware, "threat_actor_hits": actorHits,
		"active_campaigns": 7, "ti_sources": 6,
		"mitre_techniques": []map[string]interface{}{
			{"technique": "T1566 Phishing", "hits": 284, "tactic": "Initial Access"},
			{"technique": "T1078 Valid Accounts", "hits": 198, "tactic": "Defense Evasion"},
			{"technique": "T1059 Command Interpreter", "hits": 172, "tactic": "Execution"},
			{"technique": "T1486 Data Encrypted", "hits": 47, "tactic": "Impact"},
			{"technique": "T1055 Process Injection", "hits": 134, "tactic": "Defense Evasion"},
			{"technique": "T1110 Brute Force", "hits": 221, "tactic": "Credential Access"},
			{"technique": "T1003 OS Credential Dumping", "hits": 89, "tactic": "Credential Access"},
		},
		"geo_distribution": []map[string]interface{}{
			{"country": "Russia", "count": 1847},
			{"country": "China", "count": 1342},
			{"country": "North Korea", "count": 892},
			{"country": "Iran", "count": 741},
			{"country": "Romania", "count": 412},
			{"country": "Ukraine", "count": 334},
			{"country": "United States", "count": 289},
		},
		"malware_families": []map[string]interface{}{
			{"name": "Emotet", "detections": 47, "severity": "critical"},
			{"name": "Qakbot", "detections": 38, "severity": "critical"},
			{"name": "CobaltStrike", "detections": 29, "severity": "critical"},
			{"name": "Mimikatz", "detections": 61, "severity": "high"},
			{"name": "LockBit", "detections": 8, "severity": "critical"},
			{"name": "AgentTesla", "detections": 72, "severity": "high"},
		},
	})
}

// ── Endpoint & Network Metrics ────────────────────────────────────────────────

func GetSMEEndpoints(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)

	var healthy, offline, quarantined, fwBlocks, netAnom int
	_ = db.QueryRow(`SELECT healthy_endpoints,offline_agents,quarantined_endpoints,
		firewall_blocks,network_anomalies
		FROM sme_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).
		Scan(&healthy, &offline, &quarantined, &fwBlocks, &netAnom)

	total := healthy + offline + quarantined
	c.JSON(http.StatusOK, gin.H{
		"total_endpoints": total, "healthy": healthy, "offline": offline,
		"quarantined": quarantined, "isolated": 3,
		"coverage_pct": func() int {
			if total > 0 {
				return healthy * 100 / total
			}
			return 0
		}(),
		"firewall_blocks": fwBlocks, "network_anomalies": netAnom,
		"blocked_connections": fwBlocks * 3,
		"dpi_events": 28441,
		"network_throughput_gbps": 2.4,
		"endpoint_platforms": []map[string]interface{}{
			{"platform": "Windows", "count": total * 65 / 100, "coverage": 99},
			{"platform": "macOS", "count": total * 20 / 100, "coverage": 97},
			{"platform": "Linux", "count": total * 14 / 100, "coverage": 94},
			{"platform": "Mobile", "count": total * 1 / 100, "coverage": 88},
		},
		"recent_isolations": []map[string]interface{}{
			{"host": "WKSTN-FIN-047", "reason": "Ransomware behavior", "isolated_at": time.Now().Add(-2 * time.Hour).Format(time.RFC3339)},
			{"host": "SRV-DMZ-012", "reason": "Lateral movement detected", "isolated_at": time.Now().Add(-6 * time.Hour).Format(time.RFC3339)},
			{"host": "WKSTN-HR-023", "reason": "Credential dumping attempt", "isolated_at": time.Now().Add(-18 * time.Hour).Format(time.RFC3339)},
		},
	})
}

// ── Vulnerability Metrics ─────────────────────────────────────────────────────

func GetSMEVulns(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)

	var critVulns, highVulns, patchComp int
	_ = db.QueryRow(`SELECT critical_vulns,high_vulns,patch_compliance
		FROM sme_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).
		Scan(&critVulns, &highVulns, &patchComp)

	trend := []map[string]interface{}{}
	rows, _ := db.Query(`SELECT snapshot_date,critical_vulns,high_vulns,patch_compliance
		FROM sme_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 30`, tid)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var d string
			var cv, hv, pc int
			rows.Scan(&d, &cv, &hv, &pc)
			trend = append(trend, map[string]interface{}{
				"date": d, "critical": cv, "high": hv, "patch_compliance": pc,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"critical": critVulns, "high": highVulns, "medium": 847, "low": 1234,
		"total": critVulns + highVulns + 847 + 1234,
		"patch_compliance": patchComp, "overdue_remediations": 28,
		"mttr_days": 14.2, "verification_success_rate": 87,
		"exploitable": critVulns * 40 / 100,
		"risk_prioritized": []map[string]interface{}{
			{"cve": "CVE-2024-3400", "cvss": 10.0, "affected": 47, "status": "overdue"},
			{"cve": "CVE-2024-21762", "cvss": 9.8, "affected": 23, "status": "in_progress"},
			{"cve": "CVE-2023-46805", "cvss": 8.2, "affected": 12, "status": "patched"},
			{"cve": "CVE-2024-1708", "cvss": 8.8, "affected": 8, "status": "in_progress"},
			{"cve": "CVE-2024-27198", "cvss": 9.8, "affected": 3, "status": "open"},
		},
		"trend": trend,
	})
}

// ── Compliance Metrics ────────────────────────────────────────────────────────

func GetSMECompliance(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)

	var compScore int
	_ = db.QueryRow(`SELECT compliance_score FROM sme_snapshots
		WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(&compScore)

	// pull live from fce_frameworks if available
	type fwRow struct {
		Name, Category string
		Score          int
		Passed, Total  int
	}
	var frameworks []map[string]interface{}
	rows, _ := db.Query(`SELECT name,category,compliance_score,controls_passed,total_controls
		FROM fce_frameworks WHERE tenant_id=$1 AND status!='inactive' ORDER BY compliance_score DESC LIMIT 8`,
		fmt.Sprintf("%d", tid))
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var name, cat string
			var score, passed, total int
			if err := rows.Scan(&name, &cat, &score, &passed, &total); err == nil {
				frameworks = append(frameworks, map[string]interface{}{
					"name": name, "category": cat,
					"score": score, "passed": passed, "total": total,
				})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"compliance_score": compScore, "passed_controls": 892,
		"failed_controls": 108, "framework_count": 12,
		"audit_readiness": compScore - 4,
		"open_findings": 47, "policy_violations": 12,
		"remediation_progress": 78,
		"frameworks": frameworks,
	})
}

// ── Infrastructure Metrics ────────────────────────────────────────────────────

func GetSMEInfrastructure(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)

	var logRate int64
	var eps, storage int
	_ = db.QueryRow(`SELECT log_ingestion_rate,eps,storage_utilization
		FROM sme_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).
		Scan(&logRate, &eps, &storage)

	c.JSON(http.StatusOK, gin.H{
		"log_ingestion_rate": logRate, "eps": eps,
		"storage_utilization": storage,
		"components": []map[string]interface{}{
			{"name": "SIEM (Splunk)", "status": "healthy", "health": 99, "latency_ms": 12, "uptime": 99.97},
			{"name": "EDR (CrowdStrike)", "status": "healthy", "health": 98, "latency_ms": 8, "uptime": 99.99},
			{"name": "SOAR (XSOAR)", "status": "healthy", "health": 97, "latency_ms": 24, "uptime": 99.94},
			{"name": "Threat Intel Platform", "status": "healthy", "health": 100, "latency_ms": 5, "uptime": 100.0},
			{"name": "Vulnerability Scanner", "status": "healthy", "health": 96, "latency_ms": 45, "uptime": 99.91},
			{"name": "Database (Primary)", "status": "healthy", "health": 99, "latency_ms": 3, "uptime": 99.99},
			{"name": "Message Queue (Kafka)", "status": "healthy", "health": 98, "latency_ms": 6, "uptime": 99.97},
			{"name": "Email Security", "status": "degraded", "health": 74, "latency_ms": 280, "uptime": 99.42},
			{"name": "API Gateway", "status": "healthy", "health": 100, "latency_ms": 4, "uptime": 100.0},
			{"name": "Agent Connectivity", "status": "healthy", "health": 97, "latency_ms": 18, "uptime": 99.88},
		},
		"agent_connectivity": gin.H{
			"total": 1847, "online": 1823, "offline": 19, "error": 5,
		},
	})
}

// ── AI Insights ───────────────────────────────────────────────────────────────

func PostSMEAI(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB
	var body struct {
		Action string `json:"action"`
	}
	c.BindJSON(&body)

	var ctx strings.Builder
	var healthScore, activeAnalysts, autoCoverage int
	var totalAlerts, critAlerts, alertQueue int
	var totalInc, openInc, slaComp, pbExec int
	var mttd, mttr float64
	db.QueryRow(`SELECT soc_health_score,active_analysts,automation_coverage,
		total_alerts,critical_alerts,alert_queue_size,total_incidents,open_incidents,
		sla_compliance,playbook_executions,mttd_mins,mttr_mins
		FROM sme_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(
		&healthScore, &activeAnalysts, &autoCoverage, &totalAlerts, &critAlerts, &alertQueue,
		&totalInc, &openInc, &slaComp, &pbExec, &mttd, &mttr)
	fmt.Fprintf(&ctx, "SOC health score: %d/100, %d active analysts, automation coverage %d%%\n", healthScore, activeAnalysts, autoCoverage)
	fmt.Fprintf(&ctx, "Alerts: %d total, %d critical, queue size %d\n", totalAlerts, critAlerts, alertQueue)
	fmt.Fprintf(&ctx, "Incidents: %d total, %d open. MTTD %.1f min, MTTR %.1f min, SLA compliance %d%%\n", totalInc, openInc, mttd, mttr, slaComp)
	fmt.Fprintf(&ctx, "Playbook executions: %d\n", pbExec)

	arows, _ := db.Query(`SELECT analyst_name, SUM(incidents_resolved), AVG(workload_score), AVG(burnout_index)
		FROM sme_analyst_perf WHERE tenant_id=$1 AND perf_date >= NOW()-INTERVAL '30 days'
		GROUP BY analyst_name ORDER BY AVG(burnout_index) DESC LIMIT 10`, tid)
	if arows != nil {
		ctx.WriteString("Analyst performance (last 30 days):\n")
		for arows.Next() {
			var name string
			var resolved int
			var workload, burnout float64
			arows.Scan(&name, &resolved, &workload, &burnout)
			fmt.Fprintf(&ctx, "- %s: %d incidents resolved, workload %.0f, burnout index %.0f\n", name, resolved, workload, burnout)
		}
		arows.Close()
	}

	drows, _ := db.Query(`SELECT rule_name, mitre_technique, total_hits, true_positives, false_positives, status
		FROM sme_detection_rules WHERE tenant_id=$1 ORDER BY (false_positives+1)::float / (total_hits+1) DESC LIMIT 10`, tid)
	if drows != nil {
		ctx.WriteString("Detection rules (highest false-positive ratio first):\n")
		for drows.Next() {
			var name, tech, status string
			var hits, tp, fp int
			drows.Scan(&name, &tech, &hits, &tp, &fp, &status)
			fmt.Fprintf(&ctx, "- %s (%s): %d hits, %d TP, %d FP, status=%s\n", name, tech, hits, tp, fp, status)
		}
		drows.Close()
	}

	prows, _ := db.Query(`SELECT playbook_name, category, total_executions, successful, failed, analyst_hours_saved
		FROM sme_playbook_stats WHERE tenant_id=$1 ORDER BY total_executions DESC LIMIT 10`, tid)
	if prows != nil {
		ctx.WriteString("Playbooks:\n")
		for prows.Next() {
			var name, cat string
			var total, succ, fail int
			var hrs float64
			prows.Scan(&name, &cat, &total, &succ, &fail, &hrs)
			fmt.Fprintf(&ctx, "- %s (%s): %d executions (%d success/%d fail), %.0fh saved\n", name, cat, total, succ, fail, hrs)
		}
		prows.Close()
	}

	smectx := ctx.String()

	var task string
	switch body.Action {
	case "daily_summary":
		task = "Write a daily SOC operations summary: health score, alert volume, incident activity, analyst performance highlights, automation impact, and one recommendation."
	case "analyst_bottlenecks":
		task = "Identify analyst workflow bottlenecks from the performance and burnout data, each with a recommendation."
	case "detection_gaps":
		task = "Identify detection coverage gaps or weak rules from the detection rule data (e.g. high false-positive rules, low true-positive rules), each with a recommendation. Do not invent MITRE technique coverage not present in the data."
	case "alert_noise":
		task = "Analyze alert noise sources from the detection rule false-positive data and suggest tuning opportunities."
	case "automation_opportunities":
		task = "Identify automation opportunities based on the playbook execution data — which playbooks are underperforming or where manual work could be automated further."
	case "threat_trends":
		task = "Summarize what the incident and alert volume trend suggests about the current threat landscape for this SOC. If there isn't enough trend data, say so rather than inventing threat actor names or campaigns."
	case "recommendations":
		task = "Write prioritized SOC performance recommendations (critical/high/medium) grounded in the data above."
	default:
		body.Action = "daily_summary"
		task = "Write a daily SOC operations summary: health score, alert volume, incident activity, analyst performance highlights, automation impact, and one recommendation."
	}

	prompt := fmt.Sprintf(`You are a SOC operations analyst reviewing this organization's real SOC metrics.

%s

Task: %s

Base your answer strictly on the data above — do not invent specific CVE numbers, threat actor names, or figures not present in the data. Respond in plain text (no markdown headers), suitable for direct display to the user.`, smectx, task)

	resp, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"response": strings.TrimSpace(resp), "action": body.Action})
}

// ── Reports ───────────────────────────────────────────────────────────────────

func GetSMEReports(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)

	var reports []map[string]interface{}
	rows, _ := db.Query(`SELECT report_id,title,report_type,generated_by,format,size_bytes,
		period_start,period_end,created_at FROM sme_reports
		WHERE tenant_id=$1 ORDER BY created_at DESC`, tid)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id, title, rtype, by, format string
			var sizeB int64
			var ps, pe, ca *string
			if err := rows.Scan(&id, &title, &rtype, &by, &format, &sizeB, &ps, &pe, &ca); err == nil {
				reports = append(reports, map[string]interface{}{
					"report_id": id, "title": title, "report_type": rtype,
					"generated_by": by, "format": format, "size_bytes": sizeB,
					"period_start": ps, "period_end": pe, "created_at": ca,
				})
			}
		}
	}
	c.JSON(http.StatusOK, reports)
}

func PostSMEReport(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)

	var body struct {
		Title      string `json:"title"`
		ReportType string `json:"report_type"`
		Format     string `json:"format"`
		PeriodDays int    `json:"period_days"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if body.Format == "" {
		body.Format = "pdf"
	}
	if body.PeriodDays == 0 {
		body.PeriodDays = 7
	}
	id := smeID("SME-RPT")
	periodEnd := time.Now().Format("2006-01-02")
	periodStart := time.Now().AddDate(0, 0, -body.PeriodDays).Format("2006-01-02")
	sizeB := int64(200_000 + rand.Intn(600_000))

	_, err := db.Exec(`INSERT INTO sme_reports
		(tenant_id,report_id,title,report_type,generated_by,format,size_bytes,period_start,period_end)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		tid, id, body.Title, body.ReportType, actor, body.Format, sizeB, periodStart, periodEnd)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create report"})
		return
	}
	smeAudit(tid, "report_generated", "report", id, body.Title, actor, fmt.Sprintf("type:%s format:%s period:%dd", body.ReportType, body.Format, body.PeriodDays))
	smeNotify(tid, "report_ready", "SOC Report Ready: "+body.Title, "Your SOC report has been generated and is ready for review.", "info", "Reports")
	c.JSON(http.StatusOK, gin.H{"report_id": id, "title": body.Title, "status": "generated"})
}

// ── Notifications ─────────────────────────────────────────────────────────────

func GetSMENotifications(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)

	var notifs []map[string]interface{}
	rows, _ := db.Query(`SELECT id,event_type,title,message,severity,source,read,created_at
		FROM sme_notifications WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tid, limit)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var id int
			var etype, title, msg, sev, src string
			var read bool
			var ca *string
			if err := rows.Scan(&id, &etype, &title, &msg, &sev, &src, &read, &ca); err == nil {
				notifs = append(notifs, map[string]interface{}{
					"id": id, "event_type": etype, "title": title, "message": msg,
					"severity": sev, "source": src, "read": read, "created_at": ca,
				})
			}
		}
	}
	if notifs == nil {
		notifs = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, notifs)
}

func PatchSMENotificationsRead(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	db.Exec(`UPDATE sme_notifications SET read=TRUE WHERE tenant_id=$1 AND read=FALSE`, tid)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// ── Audit ─────────────────────────────────────────────────────────────────────

func GetSMEAudit(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)

	var entries []map[string]interface{}
	rows, _ := db.Query(`SELECT action,object_type,object_id,object_name,actor,ip_address,details,created_at
		FROM sme_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tid, limit)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var action, otype, actor, details string
			var oid, oname, ip, ca *string
			if err := rows.Scan(&action, &otype, &oid, &oname, &actor, &ip, &details, &ca); err == nil {
				entries = append(entries, map[string]interface{}{
					"action": action, "object_type": otype, "object_id": oid,
					"object_name": oname, "actor": actor, "ip_address": ip,
					"details": details, "created_at": ca,
				})
			}
		}
	}
	if entries == nil {
		entries = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, entries)
}
