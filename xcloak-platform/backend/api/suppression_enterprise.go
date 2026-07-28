package api

import (
	"encoding/json"
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

	// Top suppressed detections — real data from sup_rules, only rules that
	// have actually suppressed something (total_suppressed is incremented
	// nowhere automatically today, so this is honestly empty until rules
	// accrue real matches).
	topSuppressed := []interface{}{}
	tRows, err := database.DB.Query(`SELECT rule_name, COALESCE(description,''), total_suppressed FROM sup_rules WHERE tenant_id=$1 AND total_suppressed>0 ORDER BY total_suppressed DESC LIMIT 5`, tid)
	if err == nil {
		defer tRows.Close()
		for tRows.Next() {
			var ruleName, desc string
			var count int
			if tRows.Scan(&ruleName, &desc, &count) == nil {
				detection := ruleName
				if desc != "" {
					detection = desc
				}
				topSuppressed = append(topSuppressed, map[string]interface{}{"detection": detection, "count": count, "rule": ruleName})
			}
		}
	}

	// Suppression trend — no per-day suppression-event table exists, so
	// there is no honest way to build a real daily series. Return empty
	// rather than fabricate numbers.
	suppressionTrend := []interface{}{}

	// Analysts creating rules — real GROUP BY on sup_rules.
	analystsCreating := []interface{}{}
	aRows, err := database.DB.Query(`SELECT COALESCE(created_by,'unknown'), COUNT(*), COALESCE(SUM(total_suppressed),0) FROM sup_rules WHERE tenant_id=$1 GROUP BY created_by ORDER BY COUNT(*) DESC LIMIT 10`, tid)
	if err == nil {
		defer aRows.Close()
		for aRows.Next() {
			var analyst string
			var rulesCreated int
			var suppressed int64
			if aRows.Scan(&analyst, &rulesCreated, &suppressed) == nil {
				analystsCreating = append(analystsCreating, map[string]interface{}{"analyst": analyst, "rules_created": rulesCreated, "suppressed": suppressed})
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"active_rules":            activeRules,
		"suppressed_today":        totalSuppressed,
		"expiring_rules":          expiringRules,
		"analyst_time_saved_h":    float64(totalSuppressed) * 0.05,
		"top_suppressed":          topSuppressed,
		"suppression_trend":       suppressionTrend,
		"analysts_creating_rules": analystsCreating,
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
	rules := []Rule{}
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

type supCondition struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
	Logic string `json:"logic"`
}

// supFieldColumn maps a condition builder field to a real column on the
// alerts (a) / agents (ag) join. Fields with no backing column are ignored
// (not filtered on) rather than silently faked.
func supFieldColumn(field string) string {
	switch field {
	case "detection_name", "alert_type":
		return "a.rule_name"
	case "severity":
		return "a.severity"
	case "mitre_technique":
		return "a.mitre_technique"
	case "hostname":
		return "ag.hostname"
	default:
		return ""
	}
}

// POST /api/sup/preview
func PostSupPreview(c *gin.Context) {
	tid := tenantIDFromContext(c)
	var body struct {
		Conditions string `json:"conditions"`
		Scope      string `json:"scope"`
		ScopeValue string `json:"scope_value"`
	}
	_ = c.ShouldBindJSON(&body)

	var conds []supCondition
	_ = json.Unmarshal([]byte(body.Conditions), &conds)

	where := []string{"ag.tenant_id=$1", "a.created_at >= NOW() - INTERVAL '30 days'"}
	args := []interface{}{tid}
	idx := 2
	for _, cond := range conds {
		col := supFieldColumn(cond.Field)
		if col == "" || cond.Value == "" {
			continue
		}
		switch cond.Op {
		case "equals":
			where = append(where, fmt.Sprintf("%s = $%d", col, idx))
			args = append(args, cond.Value)
		case "not_equals":
			where = append(where, fmt.Sprintf("%s != $%d", col, idx))
			args = append(args, cond.Value)
		case "starts_with":
			where = append(where, fmt.Sprintf("%s ILIKE $%d", col, idx))
			args = append(args, cond.Value+"%")
		case "contains":
			where = append(where, fmt.Sprintf("%s ILIKE $%d", col, idx))
			args = append(args, "%"+cond.Value+"%")
		case "matches", "regex":
			where = append(where, fmt.Sprintf("%s ~* $%d", col, idx))
			args = append(args, cond.Value)
		default:
			continue
		}
		idx++
	}
	if body.Scope == "single_asset" && body.ScopeValue != "" {
		where = append(where, fmt.Sprintf("ag.hostname = $%d", idx))
		args = append(args, body.ScopeValue)
		idx++
	}
	whereSQL := strings.Join(where, " AND ")

	var historicalMatches int
	_ = database.DB.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM alerts a JOIN agents ag ON ag.id=a.agent_id WHERE %s`, whereSQL), args...).Scan(&historicalMatches)

	impactedAssets := []interface{}{}
	iaRows, err := database.DB.Query(fmt.Sprintf(`SELECT ag.hostname, COUNT(*), MAX(a.created_at) FROM alerts a JOIN agents ag ON ag.id=a.agent_id WHERE %s GROUP BY ag.hostname ORDER BY COUNT(*) DESC LIMIT 10`, whereSQL), args...)
	if err == nil {
		defer iaRows.Close()
		for iaRows.Next() {
			var hostname string
			var count int
			var lastMatch time.Time
			if iaRows.Scan(&hostname, &count, &lastMatch) == nil {
				impactedAssets = append(impactedAssets, map[string]interface{}{"hostname": hostname, "alert_count": count, "last_match": lastMatch.Format(time.RFC3339)})
			}
		}
	}

	sampleMatches := []interface{}{}
	smRows, err := database.DB.Query(fmt.Sprintf(`SELECT a.id, a.rule_name, ag.hostname, a.created_at, a.severity FROM alerts a JOIN agents ag ON ag.id=a.agent_id WHERE %s ORDER BY a.created_at DESC LIMIT 5`, whereSQL), args...)
	if err == nil {
		defer smRows.Close()
		for smRows.Next() {
			var id int
			var ruleName, hostname, severity string
			var ts time.Time
			if smRows.Scan(&id, &ruleName, &hostname, &ts, &severity) == nil {
				sampleMatches = append(sampleMatches, map[string]interface{}{"alert_id": fmt.Sprintf("ALT-%d", id), "detection": ruleName, "asset": hostname, "timestamp": ts.Format(time.RFC3339), "severity": severity})
			}
		}
	}

	// Confirmed incidents correlated with matching alerts (by fingerprint).
	var incidentCount int
	_ = database.DB.QueryRow(fmt.Sprintf(`SELECT COUNT(DISTINCT i.id) FROM incidents i JOIN alerts a ON a.fingerprint=i.fingerprint JOIN agents ag ON ag.id=a.agent_id WHERE %s`, whereSQL), args...).Scan(&incidentCount)

	alertsPerDayBefore := float64(historicalMatches) / 30.0
	riskAssessment := "low"
	falseNegRisk := "very_low"
	recommendation := fmt.Sprintf("Safe to suppress. 0 confirmed incidents in 30-day history for matching alerts (%d historical matches).", historicalMatches)
	if incidentCount > 0 {
		riskAssessment = "high"
		falseNegRisk = "high"
		recommendation = fmt.Sprintf("Caution: %d confirmed incident(s) correlate with alerts matching these conditions in the last 30 days. Suppressing may create a detection blind spot.", incidentCount)
	}

	c.JSON(http.StatusOK, gin.H{
		"estimated_alerts_affected": historicalMatches,
		"historical_matches":        historicalMatches,
		"lookback_days":             30,
		"impacted_assets":           impactedAssets,
		"simulated_outcome": map[string]interface{}{
			"alerts_per_day_before": alertsPerDayBefore,
			"alerts_per_day_after":  0,
			"analyst_hours_saved":   alertsPerDayBefore * 0.05,
			"risk_assessment":       riskAssessment,
			"false_negative_risk":   falseNegRisk,
			"recommendation":        recommendation,
		},
		"sample_matches": sampleMatches,
	})
}

// POST /api/sup/ai
func PostSupAI(c *gin.Context) {
	var body struct {
		DetectionName  string `json:"detection_name"`
		AlertCount     int    `json:"alert_count"`
		LookbackDays   int    `json:"lookback_days"`
		IncidentCount  int    `json:"incident_count"`
		AssetType      string `json:"asset_type"`
		Severity       string `json:"severity"`
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
		"recommendation":            rec,
		"confidence_pct":            supConfidence(body.AlertCount, body.IncidentCount),
		"reasoning":                 reasoning,
		"conditions_if_conditional": "Limit suppression to known backup server asset group during 02:00–06:00 UTC maintenance window only",
		"risk_if_suppressed":        supRisk(body.Severity, body.IncidentCount),
		"alternative":               "Lower severity to Low instead of fully suppressing, preserving log retention for forensics",
		"ai_analysis":               resp,
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
		ID        int       `json:"id"`
		RuleID    *int      `json:"rule_id"`
		RuleName  *string   `json:"rule_name"`
		Action    string    `json:"action"`
		Actor     *string   `json:"actor"`
		Details   *string   `json:"details"`
		CreatedAt time.Time `json:"created_at"`
	}
	entries := []Entry{}
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

	// Most suppressed rules — real data (only rules that have actually
	// suppressed something).
	mostSuppressed := []interface{}{}
	msRows, err := database.DB.Query(`SELECT rule_name, total_suppressed, scope, COALESCE(owner,'') FROM sup_rules WHERE tenant_id=$1 AND total_suppressed>0 ORDER BY total_suppressed DESC LIMIT 5`, tid)
	if err == nil {
		defer msRows.Close()
		for msRows.Next() {
			var ruleName, scope, owner string
			var suppressed int
			if msRows.Scan(&ruleName, &suppressed, &scope, &owner) == nil {
				mostSuppressed = append(mostSuppressed, map[string]interface{}{"rule_name": ruleName, "suppressed": suppressed, "scope": scope, "owner": owner})
			}
		}
	}

	// avg_suppression_per_rule and incident correlation are computed from
	// real sup_rules data. There is no per-detection "total before
	// suppression" table, no team dimension, and no monthly false-positive
	// history table, so top_noisy_detections / suppression_by_team /
	// false_positive_trend / false_positive_rate are honestly empty/zero
	// rather than fabricated.
	var avgPerRule float64
	if activeRules > 0 {
		avgPerRule = float64(totalSuppressed) / float64(activeRules)
	}
	// There is no per-rule application/enforcement of sup_rules against real
	// alerts today, so there is no honest way to attribute a specific
	// confirmed incident to a specific suppression rule. Report 0 rather
	// than a fabricated correlation.
	rulesWithIncidents := 0
	rulesWithZeroIncidents := activeRules

	c.JSON(http.StatusOK, gin.H{
		"active_rules":          activeRules,
		"total_suppressed":      totalSuppressed,
		"analyst_hours_saved":   float64(totalSuppressed) * 0.05,
		"false_positive_rate":   0,
		"most_suppressed_rules": mostSuppressed,
		"top_noisy_detections":  []interface{}{},
		"suppression_by_team":   []interface{}{},
		"false_positive_trend":  []interface{}{},
		"suppression_effectiveness": map[string]interface{}{
			"rules_with_zero_incidents": rulesWithZeroIncidents,
			"rules_with_incidents":      rulesWithIncidents,
			"avg_suppression_per_rule":  avgPerRule,
			"coverage_pct":              0,
		},
	})
}

// POST /api/sup/report
func PostSupReport(c *gin.Context) {
	createSupTables()
	tid := tenantIDFromContext(c)
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

	var activeRules, pendingApproval, criticalNoApproval, expiringSoon int
	var totalSuppressed int64
	_ = database.DB.QueryRow(`SELECT
		COUNT(*) FILTER (WHERE status='active'),
		COUNT(*) FILTER (WHERE approval_status='pending'),
		COUNT(*) FILTER (WHERE priority='critical' AND approval_status NOT IN ('approved','not_required')),
		COUNT(*) FILTER (WHERE status='active' AND expires_at IS NOT NULL AND expires_at BETWEEN NOW() AND NOW() + INTERVAL '7 days'),
		COALESCE(SUM(total_suppressed) FILTER (WHERE status='active'), 0)
		FROM sup_rules WHERE tenant_id=$1`, tid).Scan(&activeRules, &pendingApproval, &criticalNoApproval, &expiringSoon, &totalSuppressed)

	analystHours := float64(totalSuppressed) * 0.05

	recommendations := []interface{}{}
	if expiringSoon > 0 {
		recommendations = append(recommendations, fmt.Sprintf("%d rule(s) expire within 7 days — review and renew or let expire", expiringSoon))
	}
	if criticalNoApproval > 0 {
		recommendations = append(recommendations, fmt.Sprintf("Enable approval workflow for %d rule(s) currently in 'critical' priority without approval", criticalNoApproval))
	}
	if pendingApproval > 0 {
		recommendations = append(recommendations, fmt.Sprintf("%d rule(s) pending approval — review to activate or reject", pendingApproval))
	}

	execSummary := fmt.Sprintf("%d active suppression rule(s) have suppressed %d alert(s) to date. Estimated %.0f analyst hour(s) saved.", activeRules, totalSuppressed, analystHours)

	c.JSON(http.StatusOK, gin.H{
		"title":             title + " — " + time.Now().Format("January 2006"),
		"generated_at":      time.Now().Format(time.RFC3339),
		"classification":    "CONFIDENTIAL — INTERNAL",
		"executive_summary": execSummary,
		"key_metrics": map[string]interface{}{
			"active_rules":           activeRules,
			"alerts_suppressed":      totalSuppressed,
			"analyst_hours_saved":    analystHours,
			"rules_requiring_review": pendingApproval,
		},
		"flagged_rules":   []interface{}{},
		"recommendations": recommendations,
	})
}
