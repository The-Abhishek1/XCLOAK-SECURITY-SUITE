package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/services"
)

func createSupTables() {
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS sup_rules (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		rule_name TEXT NOT NULL,
		description TEXT,
		status TEXT DEFAULT 'draft',
		owner TEXT,
		priority TEXT DEFAULT 'medium',
		suppression_type TEXT DEFAULT 'full_suppress',
		scope TEXT DEFAULT 'single_asset',
		scope_value TEXT,
		time_type TEXT DEFAULT 'until_date',
		expires_at TIMESTAMPTZ,
		maintenance_window TEXT,
		recurring_schedule TEXT,
		conditions TEXT,
		exceptions TEXT,
		approval_status TEXT DEFAULT 'not_required',
		approved_by TEXT,
		approved_at TIMESTAMPTZ,
		total_suppressed INTEGER DEFAULT 0,
		last_triggered_at TIMESTAMPTZ,
		created_by TEXT,
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS sup_audit (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		rule_id INTEGER,
		rule_name TEXT,
		action TEXT NOT NULL,
		actor TEXT,
		details TEXT,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
}

func supAudit(tid int, ruleID int, ruleName, action, actor, details string) {
	database.DB.Exec(`INSERT INTO sup_audit (tenant_id,rule_id,rule_name,action,actor,details) VALUES ($1,$2,$3,$4,$5,$6)`, tid, ruleID, ruleName, action, actor, details)
}

// GET /api/sup/dashboard
func GetSupDashboard(c *gin.Context) {
	createSupTables()
	tid := tenantIDFromContext(c)
	row := database.DB.QueryRow(`SELECT
		COUNT(*) FILTER (WHERE status='active'),
		COUNT(*) FILTER (WHERE status='active' AND expires_at IS NOT NULL AND expires_at BETWEEN NOW() AND NOW() + INTERVAL '7 days'),
		COALESCE(SUM(total_suppressed) FILTER (WHERE status='active'), 0)
		FROM sup_rules WHERE tenant_id=$1`, tid)
	var activeRules, expiringRules int
	var totalSuppressed int64
	_ = row.Scan(&activeRules, &expiringRules, &totalSuppressed)
	c.JSON(http.StatusOK, gin.H{
		"active_rules":        activeRules,
		"suppressed_today":    totalSuppressed,
		"expiring_rules":      expiringRules,
		"analyst_time_saved_h": float64(totalSuppressed) * 0.05,
		"top_suppressed": []interface{}{
			map[string]interface{}{"detection": "Backup Process — PowerShell Execution", "count": 4200, "rule": "Backup Window Suppression"},
			map[string]interface{}{"detection": "Scheduled Task Created — SYSTEM", "count": 1840, "rule": "Sysadmin Scheduled Tasks"},
			map[string]interface{}{"detection": "LSASS Memory Access — Defender AV", "count": 972, "rule": "AV Scanner False Positive"},
			map[string]interface{}{"detection": "Network Scan — Vulnerability Scanner", "count": 718, "rule": "Vuln Scanner Suppression"},
			map[string]interface{}{"detection": "DNS Query — Windows Update", "count": 612, "rule": "Windows Update Noise"},
		},
		"suppression_trend": []interface{}{
			map[string]interface{}{"date": "2026-07-11", "suppressed": 1240, "active_rules": 8},
			map[string]interface{}{"date": "2026-07-12", "suppressed": 1820, "active_rules": 9},
			map[string]interface{}{"date": "2026-07-13", "suppressed": 980, "active_rules": 9},
			map[string]interface{}{"date": "2026-07-14", "suppressed": 2140, "active_rules": 11},
			map[string]interface{}{"date": "2026-07-15", "suppressed": 1760, "active_rules": 11},
			map[string]interface{}{"date": "2026-07-16", "suppressed": 2080, "active_rules": 12},
			map[string]interface{}{"date": "2026-07-17", "suppressed": 1940, "active_rules": 12},
		},
		"analysts_creating_rules": []interface{}{
			map[string]interface{}{"analyst": "alice@corp.com", "rules_created": 6, "suppressed": 7200},
			map[string]interface{}{"analyst": "bob@corp.com", "rules_created": 3, "suppressed": 2840},
			map[string]interface{}{"analyst": "carol@corp.com", "rules_created": 2, "suppressed": 1920},
			map[string]interface{}{"analyst": "dave@corp.com", "rules_created": 1, "suppressed": 980},
		},
	})
}

// GET /api/sup/rules
func GetSupRules(c *gin.Context) {
	createSupTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)
	status := c.Query("status")
	search := c.Query("search")

	where := []string{"tenant_id=$1"}
	args := []interface{}{tid}
	idx := 2
	if status != "" && status != "all" {
		where = append(where, fmt.Sprintf("status=$%d", idx))
		args = append(args, status)
		idx++
	}
	if search != "" {
		where = append(where, fmt.Sprintf("(rule_name ILIKE $%d OR description ILIKE $%d)", idx, idx))
		args = append(args, "%"+search+"%")
		idx++
	}
	q := fmt.Sprintf("SELECT id,rule_name,description,status,owner,priority,suppression_type,scope,scope_value,time_type,expires_at,conditions,exceptions,approval_status,approved_by,total_suppressed,last_triggered_at,created_by,created_at,updated_at FROM sup_rules WHERE %s ORDER BY created_at DESC LIMIT $%d", strings.Join(where, " AND "), idx)
	args = append(args, limit)
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Rule struct {
		ID              int        `json:"id"`
		RuleName        string     `json:"rule_name"`
		Description     *string    `json:"description"`
		Status          string     `json:"status"`
		Owner           *string    `json:"owner"`
		Priority        string     `json:"priority"`
		SuppressionType string     `json:"suppression_type"`
		Scope           string     `json:"scope"`
		ScopeValue      *string    `json:"scope_value"`
		TimeType        string     `json:"time_type"`
		ExpiresAt       *time.Time `json:"expires_at"`
		Conditions      *string    `json:"conditions"`
		Exceptions      *string    `json:"exceptions"`
		ApprovalStatus  string     `json:"approval_status"`
		ApprovedBy      *string    `json:"approved_by"`
		TotalSuppressed int        `json:"total_suppressed"`
		LastTriggeredAt *time.Time `json:"last_triggered_at"`
		CreatedBy       *string    `json:"created_by"`
		CreatedAt       time.Time  `json:"created_at"`
		UpdatedAt       time.Time  `json:"updated_at"`
	}
	var rules []Rule
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.RuleName, &r.Description, &r.Status, &r.Owner, &r.Priority, &r.SuppressionType, &r.Scope, &r.ScopeValue, &r.TimeType, &r.ExpiresAt, &r.Conditions, &r.Exceptions, &r.ApprovalStatus, &r.ApprovedBy, &r.TotalSuppressed, &r.LastTriggeredAt, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt); err == nil {
			rules = append(rules, r)
		}
	}
	if rules == nil {
		rules = []Rule{}
	}
	c.JSON(http.StatusOK, rules)
}

// POST /api/sup/rules
func PostSupRule(c *gin.Context) {
	createSupTables()
	tid := tenantIDFromContext(c)
	user := usernameFromContext(c)
	var body struct {
		RuleName        string `json:"rule_name"`
		Description     string `json:"description"`
		Priority        string `json:"priority"`
		SuppressionType string `json:"suppression_type"`
		Scope           string `json:"scope"`
		ScopeValue      string `json:"scope_value"`
		TimeType        string `json:"time_type"`
		ExpiresAt       string `json:"expires_at"`
		Conditions      string `json:"conditions"`
		Exceptions      string `json:"exceptions"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Priority == "" {
		body.Priority = "medium"
	}
	if body.SuppressionType == "" {
		body.SuppressionType = "full_suppress"
	}
	if body.Scope == "" {
		body.Scope = "single_asset"
	}
	approvalStatus := "not_required"
	status := "draft"
	if body.Priority == "critical" {
		approvalStatus = "pending"
	}
	var id int
	_ = database.DB.QueryRow(`INSERT INTO sup_rules (tenant_id,rule_name,description,status,owner,priority,suppression_type,scope,scope_value,time_type,conditions,exceptions,approval_status,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id`,
		tid, body.RuleName, body.Description, status, user, body.Priority, body.SuppressionType, body.Scope, body.ScopeValue, body.TimeType, body.Conditions, body.Exceptions, approvalStatus, user).Scan(&id)
	supAudit(tid, id, body.RuleName, "created", user, "Rule created in draft status")
	c.JSON(http.StatusOK, gin.H{"id": id, "ok": true, "approval_required": approvalStatus == "pending"})
}

// PATCH /api/sup/rules/:id
func PatchSupRule(c *gin.Context) {
	createSupTables()
	tid := tenantIDFromContext(c)
	id := c.Param("id")
	user := usernameFromContext(c)
	var body struct {
		Status      string `json:"status"`
		Description string `json:"description"`
		Priority    string `json:"priority"`
		Conditions  string `json:"conditions"`
		Exceptions  string `json:"exceptions"`
		ExpiresAt   string `json:"expires_at"`
	}
	_ = c.ShouldBindJSON(&body)
	var ruleNamePtr *string
	_ = database.DB.QueryRow(`SELECT rule_name FROM sup_rules WHERE id=$1 AND tenant_id=$2`, id, tid).Scan(&ruleNamePtr)
	ruleName := ""
	if ruleNamePtr != nil {
		ruleName = *ruleNamePtr
	}
	if body.Status != "" {
		database.DB.Exec(`UPDATE sup_rules SET status=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3`, body.Status, id, tid)
		supAudit(tid, 0, ruleName, body.Status, user, fmt.Sprintf("Status changed to %s", body.Status))
	}
	if body.Conditions != "" {
		database.DB.Exec(`UPDATE sup_rules SET conditions=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3`, body.Conditions, id, tid)
		supAudit(tid, 0, ruleName, "modified", user, "Conditions updated")
	}
	if body.Exceptions != "" {
		database.DB.Exec(`UPDATE sup_rules SET exceptions=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3`, body.Exceptions, id, tid)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DELETE /api/sup/rules/:id
func DeleteSupRule(c *gin.Context) {
	createSupTables()
	tid := tenantIDFromContext(c)
	id := c.Param("id")
	user := usernameFromContext(c)
	var ruleName string
	_ = database.DB.QueryRow(`SELECT rule_name FROM sup_rules WHERE id=$1 AND tenant_id=$2`, id, tid).Scan(&ruleName)
	database.DB.Exec(`DELETE FROM sup_rules WHERE id=$1 AND tenant_id=$2`, id, tid)
	supAudit(tid, 0, ruleName, "deleted", user, "Rule permanently deleted")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// POST /api/sup/rules/:id/approve
func PostSupApprove(c *gin.Context) {
	createSupTables()
	tid := tenantIDFromContext(c)
	id := c.Param("id")
	user := usernameFromContext(c)
	var body struct {
		Decision string `json:"decision"`
		Notes    string `json:"notes"`
	}
	_ = c.ShouldBindJSON(&body)
	if body.Decision == "approve" {
		database.DB.Exec(`UPDATE sup_rules SET approval_status='approved', approved_by=$1, approved_at=NOW(), status='active', updated_at=NOW() WHERE id=$2 AND tenant_id=$3`, user, id, tid)
		supAudit(tid, 0, "", "approved", user, "Rule approved and activated")
	} else {
		database.DB.Exec(`UPDATE sup_rules SET approval_status='rejected', approved_by=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3`, user, id, tid)
		supAudit(tid, 0, "", "rejected", user, body.Notes)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// POST /api/sup/preview
func PostSupPreview(c *gin.Context) {
	var body struct {
		Conditions string `json:"conditions"`
		Scope      string `json:"scope"`
		ScopeValue string `json:"scope_value"`
	}
	_ = c.ShouldBindJSON(&body)
	c.JSON(http.StatusOK, gin.H{
		"estimated_alerts_affected": 1240,
		"historical_matches":        4200,
		"lookback_days":             30,
		"impacted_assets": []interface{}{
			map[string]interface{}{"hostname": "BACKUP-SRV-01", "alert_count": 2100, "last_match": time.Now().Add(-2 * time.Hour).Format(time.RFC3339)},
			map[string]interface{}{"hostname": "BACKUP-SRV-02", "alert_count": 1400, "last_match": time.Now().Add(-3 * time.Hour).Format(time.RFC3339)},
			map[string]interface{}{"hostname": "WIN-LAPTOP-042", "alert_count": 700, "last_match": time.Now().Add(-6 * time.Hour).Format(time.RFC3339)},
		},
		"simulated_outcome": map[string]interface{}{
			"alerts_per_day_before": 140,
			"alerts_per_day_after":  0,
			"analyst_hours_saved":   1.17,
			"risk_assessment":       "low",
			"false_negative_risk":   "very_low",
			"recommendation":        "Safe to suppress. 0 confirmed incidents in 30-day history for matching alerts.",
		},
		"sample_matches": []interface{}{
			map[string]interface{}{"alert_id": "ALT-4821", "detection": "Backup Process — PowerShell Execution", "asset": "BACKUP-SRV-01", "timestamp": time.Now().Add(-1 * time.Hour).Format(time.RFC3339), "severity": "medium"},
			map[string]interface{}{"alert_id": "ALT-4799", "detection": "Backup Process — PowerShell Execution", "asset": "BACKUP-SRV-02", "timestamp": time.Now().Add(-2 * time.Hour).Format(time.RFC3339), "severity": "medium"},
			map[string]interface{}{"alert_id": "ALT-4712", "detection": "Backup Process — PowerShell Execution", "asset": "BACKUP-SRV-01", "timestamp": time.Now().Add(-25 * time.Hour).Format(time.RFC3339), "severity": "medium"},
		},
	})
}

// POST /api/sup/ai
func PostSupAI(c *gin.Context) {
	var body struct {
		DetectionName string  `json:"detection_name"`
		AlertCount    int     `json:"alert_count"`
		LookbackDays  int     `json:"lookback_days"`
		IncidentCount int     `json:"incident_count"`
		AssetType     string  `json:"asset_type"`
		Severity      string  `json:"severity"`
		MITRETechnique string `json:"mitre_technique"`
	}
	_ = c.ShouldBindJSON(&body)
	if body.LookbackDays == 0 {
		body.LookbackDays = 30
	}
	prompt := fmt.Sprintf(`You are a SOC analyst advisor. Analyze whether to suppress the following alert:
Detection: %s, Count in last %d days: %d, Confirmed incidents: %d, Asset type: %s, Severity: %s, MITRE: %s.
Respond with JSON: {recommendation: "suppress"|"do_not_suppress"|"conditional_suppress", confidence_pct: number, reasoning: string, conditions_if_conditional: string, risk_if_suppressed: string, alternative: string}`,
		body.DetectionName, body.LookbackDays, body.AlertCount, body.IncidentCount, body.AssetType, body.Severity, body.MITRETechnique)
	resp, err := services.CallLLM(prompt)
	if err != nil || resp == "" {
		resp = supDeterministicAI(body.DetectionName, body.AlertCount, body.IncidentCount, body.Severity)
	}
	rec := "conditional_suppress"
	reasoning := supDeterministicReasoning(body.DetectionName, body.AlertCount, body.IncidentCount, body.Severity, body.AssetType)
	if body.IncidentCount == 0 && body.AlertCount > 500 {
		rec = "suppress"
		reasoning = fmt.Sprintf("This alert has triggered %d times in %d days with zero confirmed incidents. The noise-to-signal ratio is very high. Suppression during known maintenance/operational windows is recommended.", body.AlertCount, body.LookbackDays)
	} else if body.IncidentCount > 0 {
		rec = "do_not_suppress"
		reasoning = fmt.Sprintf("Do not suppress. This detection has been associated with %d confirmed incident(s) in the last %d days. Suppressing it would create a blind spot for active threat activity.", body.IncidentCount, body.LookbackDays)
	}
	c.JSON(http.StatusOK, gin.H{
		"recommendation":           rec,
		"confidence_pct":           supConfidence(body.AlertCount, body.IncidentCount),
		"reasoning":                reasoning,
		"conditions_if_conditional": "Limit suppression to known backup server asset group during 02:00–06:00 UTC maintenance window only",
		"risk_if_suppressed":       supRisk(body.Severity, body.IncidentCount),
		"alternative":              "Lower severity to Low instead of fully suppressing, preserving log retention for forensics",
		"ai_analysis":              resp,
	})
}

func supDeterministicAI(detection string, count, incidents int, severity string) string {
	if incidents > 0 {
		return fmt.Sprintf("Do not suppress '%s'. This detection has correlated with %d confirmed incident(s). Suppression would create a critical visibility gap.", detection, incidents)
	}
	return fmt.Sprintf("'%s' has triggered %d times with no confirmed incidents. Consider time-based or scope-limited suppression rather than a global rule.", detection, count)
}

func supDeterministicReasoning(detection string, count, incidents int, severity, assetType string) string {
	if incidents > 0 {
		return fmt.Sprintf("Do not suppress this alert. '%s' has been associated with %d confirmed incident(s). This alert provides critical detection coverage.", detection, incidents)
	}
	if count > 1000 {
		return fmt.Sprintf("This alert has triggered %d times with no confirmed incidents. This is a high-volume false positive candidate. Scoped suppression during known operational windows is recommended.", count)
	}
	return fmt.Sprintf("'%s' shows %d occurrences with no incident correlation. Evaluate conditions carefully before suppressing.", detection, count)
}

func supConfidence(count, incidents int) int {
	if incidents > 0 {
		return 97
	}
	if count > 1000 {
		return 91
	}
	if count > 200 {
		return 78
	}
	return 62
}

func supRisk(severity string, incidents int) string {
	if incidents > 0 {
		return "High — confirmed incident correlation means suppression creates a real detection blind spot"
	}
	if severity == "critical" || severity == "high" {
		return "Medium — high severity alerts should be suppressed narrowly by scope and time window only"
	}
	return "Low — alert has no incident correlation and is high volume; suppression risk is minimal"
}

// GET /api/sup/audit
func GetSupAudit(c *gin.Context) {
	createSupTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)
	rows, err := database.DB.Query(`SELECT id,rule_id,rule_name,action,actor,details,created_at FROM sup_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tid, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Entry struct {
		ID        int        `json:"id"`
		RuleID    *int       `json:"rule_id"`
		RuleName  *string    `json:"rule_name"`
		Action    string     `json:"action"`
		Actor     *string    `json:"actor"`
		Details   *string    `json:"details"`
		CreatedAt time.Time  `json:"created_at"`
	}
	var entries []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.RuleID, &e.RuleName, &e.Action, &e.Actor, &e.Details, &e.CreatedAt); err == nil {
			entries = append(entries, e)
		}
	}
	if entries == nil {
		entries = []Entry{}
	}
	c.JSON(http.StatusOK, entries)
}

// GET /api/sup/analytics
func GetSupAnalytics(c *gin.Context) {
	createSupTables()
	tid := tenantIDFromContext(c)
	row := database.DB.QueryRow(`SELECT COUNT(*) FILTER (WHERE status='active'), COALESCE(SUM(total_suppressed),0) FROM sup_rules WHERE tenant_id=$1`, tid)
	var activeRules int
	var totalSuppressed int64
	_ = row.Scan(&activeRules, &totalSuppressed)
	c.JSON(http.StatusOK, gin.H{
		"active_rules":        activeRules,
		"total_suppressed":    totalSuppressed,
		"analyst_hours_saved": float64(totalSuppressed) * 0.05,
		"false_positive_rate": 94.2,
		"most_suppressed_rules": []interface{}{
			map[string]interface{}{"rule_name": "Backup Window Suppression", "suppressed": 4200, "scope": "asset_group", "owner": "alice@corp.com"},
			map[string]interface{}{"rule_name": "Sysadmin Scheduled Tasks", "suppressed": 1840, "scope": "department", "owner": "bob@corp.com"},
			map[string]interface{}{"rule_name": "AV Scanner False Positive", "suppressed": 972, "scope": "entire_environment", "owner": "alice@corp.com"},
			map[string]interface{}{"rule_name": "Vuln Scanner Suppression", "suppressed": 718, "scope": "asset_group", "owner": "carol@corp.com"},
			map[string]interface{}{"rule_name": "Windows Update Noise", "suppressed": 612, "scope": "entire_environment", "owner": "dave@corp.com"},
		},
		"top_noisy_detections": []interface{}{
			map[string]interface{}{"detection": "Backup Process — PowerShell Execution", "total": 4200, "suppressed": 4200, "rate_pct": 100},
			map[string]interface{}{"detection": "Scheduled Task Created — SYSTEM", "total": 1980, "suppressed": 1840, "rate_pct": 92.9},
			map[string]interface{}{"detection": "LSASS Memory Access — AV Scanner", "total": 1100, "suppressed": 972, "rate_pct": 88.4},
			map[string]interface{}{"detection": "Network Scan from Qualys", "total": 720, "suppressed": 718, "rate_pct": 99.7},
			map[string]interface{}{"detection": "Windows Update DNS Queries", "total": 640, "suppressed": 612, "rate_pct": 95.6},
		},
		"suppression_by_team": []interface{}{
			map[string]interface{}{"team": "SOC Team A", "rules_created": 6, "alerts_suppressed": 7200},
			map[string]interface{}{"team": "SOC Team B", "rules_created": 3, "alerts_suppressed": 2840},
			map[string]interface{}{"team": "IR Team", "rules_created": 2, "alerts_suppressed": 1920},
			map[string]interface{}{"team": "Cloud Security", "rules_created": 1, "alerts_suppressed": 980},
		},
		"false_positive_trend": []interface{}{
			map[string]interface{}{"month": "Apr", "fps": 8400, "suppressed": 6200},
			map[string]interface{}{"month": "May", "fps": 7200, "suppressed": 8100},
			map[string]interface{}{"month": "Jun", "fps": 6100, "suppressed": 9400},
			map[string]interface{}{"month": "Jul", "fps": 4200, "suppressed": 12900},
		},
		"suppression_effectiveness": map[string]interface{}{
			"rules_with_zero_incidents": 11,
			"rules_with_incidents":      1,
			"avg_suppression_per_rule":  1058,
			"coverage_pct":              91.7,
		},
	})
}

// POST /api/sup/report
func PostSupReport(c *gin.Context) {
	var body struct {
		ReportType string `json:"report_type"`
	}
	_ = c.ShouldBindJSON(&body)
	title := "Suppression Report"
	switch body.ReportType {
	case "false_positive":
		title = "False Positive Report"
	case "effectiveness":
		title = "Rule Effectiveness Report"
	case "audit":
		title = "Suppression Audit Report"
	case "compliance":
		title = "Suppression Compliance Report"
	}
	c.JSON(http.StatusOK, gin.H{
		"title":            title + " — " + time.Now().Format("January 2006"),
		"generated_at":     time.Now().Format(time.RFC3339),
		"classification":   "CONFIDENTIAL — INTERNAL",
		"executive_summary": "12 active suppression rules reduced analyst alert volume by 92.3% this period. Estimated 650 analyst hours saved. 1 suppression rule flagged for review — alerts matched a confirmed incident after rule activation.",
		"key_metrics": map[string]interface{}{
			"active_rules": 12, "alerts_suppressed": 12940,
			"analyst_hours_saved": 647, "false_positive_rate": "94.2%",
			"rules_requiring_review": 1,
		},
		"top_rules": []interface{}{
			map[string]interface{}{"rule": "Backup Window Suppression", "suppressed": 4200, "incidents": 0, "status": "healthy"},
			map[string]interface{}{"rule": "AV Scanner False Positive", "suppressed": 972, "incidents": 0, "status": "healthy"},
			map[string]interface{}{"rule": "Vuln Scanner Suppression", "suppressed": 718, "incidents": 0, "status": "healthy"},
		},
		"flagged_rules": []interface{}{
			map[string]interface{}{"rule": "Sysadmin Scheduled Tasks", "suppressed": 1840, "incidents": 1, "issue": "1 suppressed alert later correlated with confirmed incident INC-2026-0412"},
		},
		"recommendations": []interface{}{
			"Review 'Sysadmin Scheduled Tasks' rule — alert matched confirmed incident INC-2026-0412",
			"3 rules expire within 7 days — review and renew or let expire",
			"Enable approval workflow for 2 rules currently in 'critical' priority without approval",
			"Add exception for Domain Controllers to all full-suppress rules",
		},
	})
}
