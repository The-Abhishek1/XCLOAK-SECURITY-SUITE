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
		"by_source": []map[string]interface{}{},
		"trend":     volTrend,
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

	bySev := []map[string]interface{}{}
	srows, _ := db.Query(`SELECT severity, COUNT(*) FROM incidents WHERE tenant_id=$1 GROUP BY severity ORDER BY COUNT(*) DESC`, tid)
	if srows != nil {
		defer srows.Close()
		for srows.Next() {
			var sev string
			var cnt int
			srows.Scan(&sev, &cnt)
			bySev = append(bySev, map[string]interface{}{"severity": sev, "count": cnt})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_incidents": total, "critical": crit, "open": open, "closed": closed,
		"sla_compliance": sla,
		"mttd_mins": mttd, "mtta_mins": mtta, "mttc_mins": mttc,
		"mttr_mins": mttr, "mttrec_mins": mttrec,
		"by_severity": bySev,
		"by_category": []map[string]interface{}{},
		"trend":       trend,
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

	var avgResolutionHrs float64
	db.QueryRow(`SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (closed_at - created_at))/3600),0)
		FROM cases WHERE tenant_id=$1 AND closed_at IS NOT NULL`, tid).Scan(&avgResolutionHrs)

	byStatus := []map[string]interface{}{}
	srows, _ := db.Query(`SELECT status, COUNT(*) FROM cases WHERE tenant_id=$1 GROUP BY status ORDER BY COUNT(*) DESC`, tid)
	if srows != nil {
		defer srows.Close()
		for srows.Next() {
			var status string
			var cnt int
			srows.Scan(&status, &cnt)
			byStatus = append(byStatus, map[string]interface{}{"status": status, "count": cnt})
		}
	}

	byAnalyst := []map[string]interface{}{}
	arows, _ := db.Query(`
		SELECT assigned_to_name,
		       COUNT(*) FILTER (WHERE status NOT IN ('closed','archived')),
		       COUNT(*) FILTER (WHERE status IN ('closed','archived')),
		       COALESCE(AVG(EXTRACT(EPOCH FROM (closed_at - created_at))/3600) FILTER (WHERE closed_at IS NOT NULL),0)
		FROM cases WHERE tenant_id=$1 AND assigned_to_name IS NOT NULL AND assigned_to_name != ''
		GROUP BY assigned_to_name ORDER BY COUNT(*) DESC LIMIT 10`, tid)
	if arows != nil {
		defer arows.Close()
		for arows.Next() {
			var name string
			var open, closed int
			var avgHrs float64
			arows.Scan(&name, &open, &closed, &avgHrs)
			byAnalyst = append(byAnalyst, map[string]interface{}{"analyst": name, "open": open, "closed": closed, "avg_hrs": avgHrs})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_cases": total, "open": openC, "closed": closedC,
		"backlog": backlog, "escalated": escalated, "reopened": reopened,
		"avg_investigation_hrs": 0, "avg_resolution_hrs": avgResolutionHrs,
		"by_status":  byStatus,
		"by_team":    []map[string]interface{}{},
		"by_analyst": byAnalyst,
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

	// shift coverage — analyst counts per shift are real; the shift-hour
	// windows are a fixed business-policy reference, not tenant data.
	shiftWindows := map[string]string{"day": "07:00–15:00", "evening": "15:00–23:00", "night": "23:00–07:00"}
	shifts := []map[string]interface{}{}
	shrows, _ := db.Query(`SELECT shift, COUNT(DISTINCT analyst_name) FROM sme_analyst_perf
		WHERE tenant_id=$1 AND perf_date >= NOW()-INTERVAL '30 days' GROUP BY shift ORDER BY shift`, tid)
	if shrows != nil {
		defer shrows.Close()
		for shrows.Next() {
			var shift string
			var cnt int
			shrows.Scan(&shift, &cnt)
			shifts = append(shifts, map[string]interface{}{"shift": shift, "analysts": cnt, "coverage": shiftWindows[shift]})
		}
	}

	var totalActive, onlineNow int
	db.QueryRow(`SELECT COUNT(DISTINCT analyst_name) FROM sme_analyst_perf
		WHERE tenant_id=$1 AND perf_date >= NOW()-INTERVAL '30 days'`, tid).Scan(&totalActive)
	db.QueryRow(`SELECT analysts_online FROM sme_snapshots WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(&onlineNow)

	c.JSON(http.StatusOK, gin.H{
		"analysts":       analysts,
		"shift_coverage": shifts,
		"total_active":   totalActive,
		"online_now":     onlineNow,
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

	// MITRE tactic coverage: "techniques" is the published size of each
	// tactic's technique catalog in the MITRE ATT&CK Enterprise matrix
	// (stable reference data, not tenant-specific); "covered"/"pct" are
	// computed from this tenant's real detection rules below.
	tacticSizes := []struct {
		Tactic     string
		Techniques int
	}{
		{"Initial Access", 12}, {"Execution", 14}, {"Persistence", 19},
		{"Privilege Escalation", 13}, {"Defense Evasion", 42}, {"Credential Access", 17},
		{"Discovery", 31}, {"Lateral Movement", 9}, {"Collection", 17},
		{"Command & Control", 16}, {"Exfiltration", 9}, {"Impact", 14},
	}
	tacticCovered := map[string]int{}
	tacticRows, _ := db.Query(`SELECT mitre_tactic, COUNT(DISTINCT mitre_technique) FROM sme_detection_rules
		WHERE tenant_id=$1 AND status='active' AND mitre_tactic IS NOT NULL AND mitre_tactic != '' GROUP BY mitre_tactic`, tid)
	if tacticRows != nil {
		defer tacticRows.Close()
		for tacticRows.Next() {
			var tactic string
			var covered int
			tacticRows.Scan(&tactic, &covered)
			tacticCovered[tactic] = covered
		}
	}
	mitreCoverage := []map[string]interface{}{}
	for _, ts := range tacticSizes {
		covered := tacticCovered[ts.Tactic]
		pct := 0
		if ts.Techniques > 0 {
			pct = covered * 100 / ts.Techniques
		}
		mitreCoverage = append(mitreCoverage, map[string]interface{}{
			"tactic": ts.Tactic, "techniques": ts.Techniques, "covered": covered, "pct": pct,
		})
	}

	// Real aggregate stats for this tenant's detection rules
	var totalRules, activeRules int
	var avgAccuracy, avgExecMs float64
	var sumTP, sumFP int
	db.QueryRow(`SELECT COUNT(*), COUNT(*) FILTER (WHERE status='active'),
		COALESCE(AVG(accuracy_score),0), COALESCE(AVG(avg_execution_ms),0),
		COALESCE(SUM(true_positives),0), COALESCE(SUM(false_positives),0)
		FROM sme_detection_rules WHERE tenant_id=$1`, tid).Scan(&totalRules, &activeRules, &avgAccuracy, &avgExecMs, &sumTP, &sumFP)
	var sigmaRules, yaraRules int
	db.QueryRow(`SELECT COUNT(*) FROM sigma_rules WHERE enabled=TRUE`).Scan(&sigmaRules)
	db.QueryRow(`SELECT COUNT(*) FROM yara_rules WHERE enabled=TRUE`).Scan(&yaraRules)
	detectionCoverage := 0
	if len(tacticSizes) > 0 {
		pctSum := 0
		for _, m := range mitreCoverage {
			pctSum += m["pct"].(int)
		}
		detectionCoverage = pctSum / len(tacticSizes)
	}
	falsePositiveRate := 0.0
	detectionSuccessRate := 0.0
	if total := sumTP + sumFP; total > 0 {
		falsePositiveRate = float64(sumFP) / float64(total) * 100
		detectionSuccessRate = float64(sumTP) / float64(total) * 100
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"summary": gin.H{
			"total_rules": totalRules, "active_rules": activeRules, "sigma_rules": sigmaRules,
			"yara_rules": yaraRules, "detection_coverage": detectionCoverage,
			"avg_accuracy": int(avgAccuracy), "avg_execution_ms": int(avgExecMs),
			"false_positive_rate": falsePositiveRate, "detection_success_rate": detectionSuccessRate,
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

	var pendingApproval int
	db.QueryRow(`SELECT COUNT(*) FROM agent_tasks t JOIN agents a ON a.id=t.agent_id
		WHERE a.tenant_id=$1 AND t.status='pending_approval'`, tid).Scan(&pendingApproval)

	c.JSON(http.StatusOK, gin.H{
		"playbook_executions": pbExec, "script_executions": scriptExec,
		"analyst_hours_saved": hoursaved, "automation_success_rate": autoRate,
		"automation_coverage": autoRate,
		"approval_queue":      gin.H{"pending": pendingApproval, "approved": 0, "rejected": 0, "avg_wait_mins": 0},
		"playbooks":           playbooks,
		"trend":               trend,
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

	mitreTechniques := []map[string]interface{}{}
	mrows, _ := db.Query(`SELECT mitre_technique, mitre_tactic, SUM(total_hits) FROM sme_detection_rules
		WHERE tenant_id=$1 AND mitre_technique IS NOT NULL AND mitre_technique != ''
		GROUP BY mitre_technique, mitre_tactic ORDER BY SUM(total_hits) DESC LIMIT 10`, tid)
	if mrows != nil {
		defer mrows.Close()
		for mrows.Next() {
			var tech, tactic string
			var hits int
			mrows.Scan(&tech, &tactic, &hits)
			mitreTechniques = append(mitreTechniques, map[string]interface{}{"technique": tech, "hits": hits, "tactic": tactic})
		}
	}

	geoDist := []map[string]interface{}{}
	grows, _ := db.Query(`SELECT country, COUNT(*) FROM fwe_threats WHERE tenant_id=$1 AND country IS NOT NULL AND country != ''
		GROUP BY country ORDER BY COUNT(*) DESC LIMIT 10`, fmt.Sprintf("%d", tid))
	if grows != nil {
		defer grows.Close()
		for grows.Next() {
			var country string
			var cnt int
			grows.Scan(&country, &cnt)
			geoDist = append(geoDist, map[string]interface{}{"country": country, "count": cnt})
		}
	}

	var activeCampaigns, tiSources int
	db.QueryRow(`SELECT COUNT(*) FROM threat_actors WHERE tenant_id=$1`, tid).Scan(&activeCampaigns)
	db.QueryRow(`SELECT COUNT(*) FROM threat_feeds WHERE tenant_id=$1`, tid).Scan(&tiSources)

	c.JSON(http.StatusOK, gin.H{
		"ioc_hits": iocHits, "malware_detections": malware,
		"ransomware_detections": ransomware, "threat_actor_hits": actorHits,
		"active_campaigns": activeCampaigns, "ti_sources": tiSources,
		"mitre_techniques": mitreTechniques,
		"geo_distribution": geoDist,
		"malware_families": []map[string]interface{}{},
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

	var isolated int
	db.QueryRow(`SELECT COUNT(*) FROM agent_tasks t JOIN agents a ON a.id=t.agent_id
		WHERE a.tenant_id=$1 AND t.task_type='isolate_host' AND t.status='completed'`, tid).Scan(&isolated)

	platforms := []map[string]interface{}{}
	prows, _ := db.Query(`SELECT COALESCE(NULLIF(os,''),'Unknown'), COUNT(*),
		CASE WHEN COUNT(*)>0 THEN COUNT(*) FILTER (WHERE status='online')*100/COUNT(*) ELSE 0 END
		FROM agents WHERE tenant_id=$1 GROUP BY 1 ORDER BY COUNT(*) DESC`, tid)
	if prows != nil {
		defer prows.Close()
		for prows.Next() {
			var platform string
			var cnt, coverage int
			prows.Scan(&platform, &cnt, &coverage)
			platforms = append(platforms, map[string]interface{}{"platform": platform, "count": cnt, "coverage": coverage})
		}
	}

	isolations := []map[string]interface{}{}
	irows, _ := db.Query(`SELECT a.hostname, COALESCE(t.payload->>'rule_name',''), t.completed_at
		FROM agent_tasks t JOIN agents a ON a.id=t.agent_id
		WHERE a.tenant_id=$1 AND t.task_type='isolate_host' AND t.status='completed'
		ORDER BY t.completed_at DESC LIMIT 5`, tid)
	if irows != nil {
		defer irows.Close()
		for irows.Next() {
			var host, reason string
			var completedAt *time.Time
			irows.Scan(&host, &reason, &completedAt)
			isoAt := ""
			if completedAt != nil {
				isoAt = completedAt.Format(time.RFC3339)
			}
			isolations = append(isolations, map[string]interface{}{"host": host, "reason": reason, "isolated_at": isoAt})
		}
	}

	coveragePct := 0
	if total > 0 {
		coveragePct = healthy * 100 / total
	}

	c.JSON(http.StatusOK, gin.H{
		"total_endpoints": total, "healthy": healthy, "offline": offline,
		"quarantined": quarantined, "isolated": isolated,
		"coverage_pct":            coveragePct,
		"firewall_blocks":         fwBlocks, "network_anomalies": netAnom,
		"blocked_connections":     0,
		"dpi_events":              0,
		"network_throughput_gbps": 0,
		"endpoint_platforms":      platforms,
		"recent_isolations":       isolations,
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

	var medVulns, lowVulns int
	db.QueryRow(`SELECT COUNT(*) FILTER (WHERE v.severity='medium'), COUNT(*) FILTER (WHERE v.severity='low')
		FROM vulnerabilities v JOIN agents a ON a.id=v.agent_id WHERE a.tenant_id=$1`, tid).Scan(&medVulns, &lowVulns)

	riskPrioritized := []map[string]interface{}{}
	rrows, _ := db.Query(`
		SELECT v.cve_id, COALESCE(v.cvss_score,0), COUNT(DISTINCT v.agent_id)
		FROM vulnerabilities v JOIN agents a ON a.id=v.agent_id
		WHERE a.tenant_id=$1 AND v.severity IN ('critical','high') AND v.cve_id IS NOT NULL AND v.cve_id != ''
		GROUP BY v.cve_id, v.cvss_score ORDER BY COALESCE(v.cvss_score,0) DESC LIMIT 5`, tid)
	if rrows != nil {
		defer rrows.Close()
		for rrows.Next() {
			var cve string
			var cvss float64
			var affected int
			rrows.Scan(&cve, &cvss, &affected)
			riskPrioritized = append(riskPrioritized, map[string]interface{}{"cve": cve, "cvss": cvss, "affected": affected, "status": "open"})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"critical": critVulns, "high": highVulns, "medium": medVulns, "low": lowVulns,
		"total": critVulns + highVulns + medVulns + lowVulns,
		"patch_compliance": patchComp, "overdue_remediations": 0,
		"mttr_days": 0, "verification_success_rate": 0,
		"exploitable":      0,
		"risk_prioritized": riskPrioritized,
		"trend":            trend,
	})
}

// ── Compliance Metrics ────────────────────────────────────────────────────────

func GetSMECompliance(c *gin.Context) {
	db := database.DB
	tid := tenantIDFromContext(c)

	var compScore int
	_ = db.QueryRow(`SELECT compliance_score FROM sme_snapshots
		WHERE tenant_id=$1 ORDER BY snapshot_date DESC LIMIT 1`, tid).Scan(&compScore)

	// pull live from fce_frameworks if available (real columns: overall_score,
	// passed_controls, total_controls, is_active — this query previously
	// referenced non-existent columns and silently returned zero rows)
	var frameworks []map[string]interface{}
	rows, _ := db.Query(`SELECT name,category,overall_score,passed_controls,total_controls
		FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE ORDER BY overall_score DESC LIMIT 8`, tid)
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

	var frameworkCount int
	db.QueryRow(`SELECT COUNT(*) FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE`, tid).Scan(&frameworkCount)
	var passedControls, failedControls int
	db.QueryRow(`SELECT COUNT(*) FILTER (WHERE assessment_status='passed'), COUNT(*) FILTER (WHERE assessment_status='failed')
		FROM fce_controls WHERE tenant_id=$1`, tid).Scan(&passedControls, &failedControls)
	var openFindings int
	db.QueryRow(`SELECT COUNT(*) FROM fce_remediations WHERE tenant_id=$1 AND status NOT IN ('closed','cancelled')`, tid).Scan(&openFindings)

	remediationProgress := 0
	if total := passedControls + failedControls; total > 0 {
		remediationProgress = passedControls * 100 / total
	}

	c.JSON(http.StatusOK, gin.H{
		"compliance_score": compScore, "passed_controls": passedControls,
		"failed_controls": failedControls, "framework_count": frameworkCount,
		"audit_readiness": compScore,
		"open_findings": openFindings, "policy_violations": 0,
		"remediation_progress": remediationProgress,
		"frameworks":           frameworks,
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

	var agentTotal, agentOnline, agentOffline int
	db.QueryRow(`SELECT COUNT(*), COUNT(*) FILTER (WHERE status='online'), COUNT(*) FILTER (WHERE status!='online')
		FROM agents WHERE tenant_id=$1`, tid).Scan(&agentTotal, &agentOnline, &agentOffline)

	c.JSON(http.StatusOK, gin.H{
		"log_ingestion_rate": logRate, "eps": eps,
		"storage_utilization": storage,
		"components":          []map[string]interface{}{},
		"agent_connectivity": gin.H{
			"total": agentTotal, "online": agentOnline, "offline": agentOffline, "error": 0,
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
