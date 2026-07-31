package services

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"xcloak-platform/database"
)

func rpeReportAudit(tid int, action, objType, objID, objName, actor, details string) {
	database.DB.Exec(`INSERT INTO rpe_audit (tenant_id,action,object_type,object_id,object_name,actor,details) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		tid, action, objType, objID, objName, actor, details)
}

func rpeReportNotify(tid int, eventType, title, message, severity, reportID, reportName string) {
	database.DB.Exec(`INSERT INTO rpe_notifications (tenant_id,event_type,title,message,severity,report_id,report_name) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		tid, eventType, title, message, severity, reportID, reportName)
}

func rpeReportID(prefix string) string {
	return fmt.Sprintf("%s-%06d", prefix, time.Now().UnixNano()%999999)
}

// gatherRPEContext pulls the same real cross-cutting security data
// api.PostRPEAI already gathers for its AI prompts (alerts/incidents/
// vulnerabilities/compliance) — the actual substance of a "security
// report" on this page. Shared here so both a manual Generate click and a
// scheduled run produce identical, real content.
func gatherRPEContext(tid int) (ctxText string, keyMetrics map[string]any) {
	db := database.DB
	var ctx strings.Builder
	var totalAlerts, critAlerts, highAlerts int
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '30 days'`, tid).Scan(&totalAlerts)
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '30 days' AND severity='critical'`, tid).Scan(&critAlerts)
	db.QueryRow(`SELECT COUNT(*) FROM alerts WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '30 days' AND severity='high'`, tid).Scan(&highAlerts)
	fmt.Fprintf(&ctx, "Alerts (last 30 days): %d total, %d critical, %d high\n", totalAlerts, critAlerts, highAlerts)

	var openIncidents, closedIncidents int
	db.QueryRow(`SELECT COUNT(*) FROM incidents WHERE tenant_id=$1 AND status='open'`, tid).Scan(&openIncidents)
	db.QueryRow(`SELECT COUNT(*) FROM incidents WHERE tenant_id=$1 AND status='closed' AND updated_at>=NOW()-INTERVAL '30 days'`, tid).Scan(&closedIncidents)
	fmt.Fprintf(&ctx, "Incidents: %d open, %d closed in last 30 days\n", openIncidents, closedIncidents)

	var openVulns, criticalVulns int
	db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE tenant_id=$1 AND patch_status IN ('open','in_progress')`, tid).Scan(&openVulns)
	db.QueryRow(`SELECT COUNT(*) FROM vulnerabilities WHERE tenant_id=$1 AND patch_status IN ('open','in_progress') AND severity='critical'`, tid).Scan(&criticalVulns)
	fmt.Fprintf(&ctx, "Vulnerabilities: %d open (%d critical)\n", openVulns, criticalVulns)

	var avgCompliance float64
	db.QueryRow(`SELECT COALESCE(AVG(overall_score),0) FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE`, tid).Scan(&avgCompliance)
	fmt.Fprintf(&ctx, "Average compliance score across active frameworks: %.0f%%\n", avgCompliance)

	keyMetrics = map[string]any{
		"total_alerts_30d":   totalAlerts,
		"critical_alerts":    critAlerts,
		"open_incidents":     openIncidents,
		"open_vulns":         openVulns,
		"critical_vulns":     criticalVulns,
		"avg_compliance_pct": int(avgCompliance),
	}
	return ctx.String(), keyMetrics
}

// GenerateRPEReport produces a real report: real cross-cutting metrics plus
// an LLM-grounded executive summary/recommendations, matching the pattern
// used by every other page's report endpoint this phase. It used to be a
// hardcoded comment — "// Simulate execution" — with duration_ms/
// file_size_bytes as pure random numbers and a download_url pointing at a
// route that was never registered anywhere (every Download link on this
// page 404'd). The generated content is now stored in rpe_exports.content
// and served for real by GetRPEDownload. Lives in services (not api, where
// PostRPEGenerate calls it from) so the scheduler tick — which can't import
// api without a cycle — can dispatch scheduled report runs through the
// same real generation path a manual click uses.
func GenerateRPEReport(tid int, reportID, reportName, actor, format, triggerSource string) (execID string, err error) {
	start := time.Now()
	reportCtx, keyMetrics := gatherRPEContext(tid)

	prompt := fmt.Sprintf(`You are a SOC reporting analyst writing a security report titled %q for this organization, using its real security data below.

%s

Respond as a JSON object with fields: executive_summary (2-4 sentences grounded only in the data above, no invented CVEs/IPs/asset names), recommendations (a JSON array of up to 5 short actionable strings based only on this real data — if there isn't enough data, say so instead of inventing findings).`, reportName, reportCtx)

	var summary string
	var recommendations []string
	if raw, llmErr := CallLLM(prompt); llmErr == nil {
		clean := raw
		if idx := strings.Index(clean, "```json"); idx != -1 {
			clean = clean[idx+7:]
		} else if idx := strings.Index(clean, "```"); idx != -1 {
			clean = clean[idx+3:]
		}
		if idx := strings.LastIndex(clean, "```"); idx != -1 {
			clean = clean[:idx]
		}
		var parsed struct {
			ExecutiveSummary string   `json:"executive_summary"`
			Recommendations  []string `json:"recommendations"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(clean)), &parsed) == nil {
			summary = parsed.ExecutiveSummary
			recommendations = parsed.Recommendations
		}
	}
	if summary == "" {
		summary = fmt.Sprintf("%d alerts recorded in the last 30 days (%d critical), %d open incidents, %d open vulnerabilities (%d critical), average compliance score %d%%.",
			keyMetrics["total_alerts_30d"], keyMetrics["critical_alerts"], keyMetrics["open_incidents"],
			keyMetrics["open_vulns"], keyMetrics["critical_vulns"], keyMetrics["avg_compliance_pct"])
		recommendations = []string{}
	}

	generatedAt := time.Now()
	content := map[string]any{
		"title":             reportName,
		"generated_at":      generatedAt.Format(time.RFC3339),
		"generated_by":      actor,
		"classification":    "CONFIDENTIAL",
		"executive_summary": summary,
		"key_metrics":       keyMetrics,
		"recommendations":   recommendations,
	}

	// No PDF/DOCX/XLSX rendering engine exists anywhere in this codebase —
	// rather than fabricate a binary format this can't actually produce,
	// json/csv get their real native shape and everything else (pdf/html/
	// docx/xlsx were all offered as export_format choices in the UI) gets
	// the same real content as a readable plain-text report instead of a
	// falsely-labeled binary file.
	var contentStr, ext string
	switch format {
	case "json":
		b, _ := json.MarshalIndent(content, "", "  ")
		contentStr, ext = string(b), "json"
	case "csv":
		var sb strings.Builder
		sb.WriteString("metric,value\n")
		for k, v := range keyMetrics {
			fmt.Fprintf(&sb, "%s,%v\n", k, v)
		}
		contentStr, ext = sb.String(), "csv"
	default:
		var sb strings.Builder
		fmt.Fprintf(&sb, "%s\nGenerated %s by %s\nClassification: CONFIDENTIAL\n\nEXECUTIVE SUMMARY\n%s\n\nKEY METRICS\n", reportName, generatedAt.Format(time.RFC3339), actor, summary)
		for k, v := range keyMetrics {
			fmt.Fprintf(&sb, "- %s: %v\n", k, v)
		}
		if len(recommendations) > 0 {
			sb.WriteString("\nRECOMMENDATIONS\n")
			for i, r := range recommendations {
				fmt.Fprintf(&sb, "%d. %s\n", i+1, r)
			}
		}
		contentStr, ext = sb.String(), "txt"
	}

	execID = rpeReportID("EXC")
	durMs := int(time.Since(start).Milliseconds())
	fileSize := int64(len(contentStr))
	downloadURL := fmt.Sprintf("/api/rpe/download/%s", execID)

	database.DB.Exec(
		`INSERT INTO rpe_executions (tenant_id, execution_id, report_id, report_name, started_at, completed_at, duration_ms, status, export_format, triggered_by, executed_by, file_size_bytes, download_url)
		 VALUES ($1,$2,$3,$4,$5,NOW(),$6,'completed',$7,$8,$9,$10,$11)`,
		tid, execID, reportID, reportName, start, durMs, format, triggerSource, actor, fileSize, downloadURL,
	)
	database.DB.Exec(
		`UPDATE rpe_reports SET last_generated_at=NOW(), last_generated_by=$1, generation_count=generation_count+1, updated_at=NOW() WHERE report_id=$2 AND tenant_id=$3`,
		actor, reportID, tid,
	)
	expID := rpeReportID("EXP")
	database.DB.Exec(
		`INSERT INTO rpe_exports (tenant_id, export_id, report_id, report_name, execution_id, format, file_size_bytes, exported_by, download_url, content)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		tid, expID, reportID, reportName, execID, ext, fileSize, actor, downloadURL, contentStr,
	)
	rpeReportAudit(tid, "report_generated", "report", reportID, reportName, actor, fmt.Sprintf("Format: %s, Size: %d bytes", ext, fileSize))
	rpeReportNotify(tid, "report_generated", "Report Generated", fmt.Sprintf("'%s' generated successfully (%s)", reportName, ext), "info", reportID, reportName)

	return execID, nil
}

// NextRPERunTime computes next_run_at for a schedule frequency/cron_expr —
// this used to be hardcoded to "now + 24h" regardless of the selected
// frequency (hourly/daily/weekly/monthly/quarterly/yearly/cron), so e.g. a
// "monthly" schedule would silently re-fire every day. Returns UTC times —
// see Script Runner's/Scheduled Tasks' identical fix for why: a naive
// local time.Now() on a non-UTC server writes wall-clock digits that
// compare incorrectly against Postgres's own NOW().
func NextRPERunTime(frequency, cronExpr string) *time.Time {
	now := time.Now().UTC()
	var t time.Time
	switch frequency {
	case "one_time", "hourly":
		t = now.Add(time.Hour)
	case "daily":
		t = now.AddDate(0, 0, 1)
	case "weekly":
		t = now.AddDate(0, 0, 7)
	case "monthly":
		t = now.AddDate(0, 1, 0)
	case "quarterly":
		t = now.AddDate(0, 3, 0)
	case "yearly":
		t = now.AddDate(1, 0, 0)
	case "cron":
		t = NextRunTime(cronExpr)
	default:
		t = now.AddDate(0, 0, 1)
	}
	return &t
}

// RunDueRPESchedules dispatches rpe_schedules whose next_run_at has passed,
// through the same GenerateRPEReport path a manual "Generate" click uses,
// then advances last_run_at/next_run_at/run_count so each schedule
// actually recurs at its real configured frequency instead of firing once
// at creation (since nothing ever dispatched due schedules at all before
// this) and going stale forever.
func RunDueRPESchedules() {
	rows, err := database.DB.Query(`
		SELECT id, tenant_id, schedule_id, report_id, report_name, frequency, cron_expr, export_format
		FROM rpe_schedules
		WHERE status='active' AND next_run_at IS NOT NULL AND next_run_at <= NOW()`)
	if err != nil {
		return
	}
	type dueSchedule struct {
		id, tenantID                                        int
		scheduleID, reportID, reportName, frequency, format string
		cronExpr                                            *string
	}
	due := []dueSchedule{}
	for rows.Next() {
		var d dueSchedule
		if rows.Scan(&d.id, &d.tenantID, &d.scheduleID, &d.reportID, &d.reportName, &d.frequency, &d.cronExpr, &d.format) == nil {
			due = append(due, d)
		}
	}
	rows.Close()

	for _, d := range due {
		_, err := GenerateRPEReport(d.tenantID, d.reportID, d.reportName, "scheduler", d.format, "scheduled")
		next := NextRPERunTime(d.frequency, "")
		if d.cronExpr != nil {
			next = NextRPERunTime(d.frequency, *d.cronExpr)
		}
		if err != nil {
			database.DB.Exec(`UPDATE rpe_schedules SET last_run_at=NOW(), next_run_at=$1, run_count=run_count+1, failure_count=failure_count+1 WHERE id=$2`, next, d.id)
			continue
		}
		database.DB.Exec(`UPDATE rpe_schedules SET last_run_at=NOW(), next_run_at=$1, run_count=run_count+1, success_count=success_count+1 WHERE id=$2`, next, d.id)
	}
}
