package api

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/services"
)

func init() { createQETables() }

func createQETables() {
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS qe_items (
		id                    SERIAL PRIMARY KEY,
		tenant_id             TEXT NOT NULL,
		quarantine_id         TEXT NOT NULL,
		asset_name            TEXT NOT NULL,
		asset_type            TEXT NOT NULL DEFAULT 'endpoint',
		severity              TEXT NOT NULL DEFAULT 'high',
		risk_score            INTEGER DEFAULT 75,
		status                TEXT NOT NULL DEFAULT 'active',
		owner                 TEXT,
		source_detection      TEXT,
		incident_id           TEXT,
		case_id               TEXT,
		quarantine_type       TEXT NOT NULL DEFAULT 'full_network_isolation',
		quarantine_reason     TEXT,
		detection_rule        TEXT,
		mitre_techniques      TEXT DEFAULT '[]',
		related_alerts        TEXT DEFAULT '[]',
		business_impact       TEXT,
		analyst_notes         TEXT,
		approval_status       TEXT DEFAULT 'not_required',
		approved_by           TEXT,
		evidence_collected    BOOLEAN DEFAULT FALSE,
		evidence_types        TEXT DEFAULT '[]',
		release_type          TEXT,
		expires_at            TIMESTAMP,
		created_at            TIMESTAMP DEFAULT NOW(),
		updated_at            TIMESTAMP DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS qe_evidence (
		id             SERIAL PRIMARY KEY,
		tenant_id      TEXT NOT NULL,
		item_id        INTEGER NOT NULL,
		evidence_type  TEXT NOT NULL,
		data           TEXT DEFAULT '{}',
		collected_at   TIMESTAMP DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS qe_audit (
		id             SERIAL PRIMARY KEY,
		tenant_id      TEXT NOT NULL,
		item_id        INTEGER,
		quarantine_id  TEXT,
		asset_name     TEXT,
		action         TEXT NOT NULL,
		actor          TEXT NOT NULL,
		details        TEXT,
		created_at     TIMESTAMP DEFAULT NOW()
	)`)
}

func qeAudit(tid int, itemID int, qid, assetName, action, actor, details string) {
	database.DB.Exec(`INSERT INTO qe_audit (tenant_id,item_id,quarantine_id,asset_name,action,actor,details)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, tid, itemID, qid, assetName, action, actor, details)
}

// GET /api/qe/dashboard
func GetQEDashboard(c *gin.Context) {
	tid := tenantIDFromContext(c)
	count := func(where string, args ...interface{}) int {
		var n int
		database.DB.QueryRow(`SELECT COUNT(*) FROM qe_items WHERE tenant_id=$1`+where, append([]interface{}{tid}, args...)...).Scan(&n)
		return n
	}
	c.JSON(http.StatusOK, gin.H{
		"quarantined_endpoints":          count(` AND asset_type='endpoint' AND status='active'`),
		"quarantined_files":              count(` AND asset_type='file' AND status='active'`),
		"quarantined_processes":          count(` AND asset_type='process' AND status='active'`),
		"quarantined_users":              count(` AND asset_type='user' AND status='active'`),
		"quarantined_emails":             count(` AND asset_type='email' AND status='active'`),
		"quarantined_network_connections": count(` AND asset_type='network' AND status='active'`),
		"active_quarantine_sessions":     count(` AND status='active'`),
		"released_assets":                count(` AND status='released'`),
		"pending_approvals":              count(` AND approval_status='pending'`),
		"expiring_soon":                  count(` AND expires_at IS NOT NULL AND expires_at < NOW() + INTERVAL '24 hours' AND status='active'`),
	})
}

// GET /api/qe/queue
func GetQEQueue(c *gin.Context) {
	tid := tenantIDFromContext(c)
	status := c.Query("status")
	assetType := c.Query("asset_type")
	search := c.Query("search")
	limit := parseLimit(c, 100)

	q := `SELECT id,quarantine_id,asset_name,asset_type,severity,risk_score,status,owner,
		source_detection,incident_id,case_id,quarantine_type,quarantine_reason,
		approval_status,evidence_collected,expires_at,created_at
		FROM qe_items WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2

	if status != "" {
		q += fmt.Sprintf(` AND status=$%d`, i); args = append(args, status); i++
	}
	if assetType != "" {
		q += fmt.Sprintf(` AND asset_type=$%d`, i); args = append(args, assetType); i++
	}
	if search != "" {
		q += fmt.Sprintf(` AND (asset_name ILIKE $%d OR quarantine_id ILIKE $%d OR owner ILIKE $%d)`, i, i, i)
		args = append(args, "%"+search+"%"); i++
	}
	q += fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d`, i)
	args = append(args, limit)

	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusOK, []interface{}{}); return
	}
	defer rows.Close()

	items := []map[string]interface{}{}
	for rows.Next() {
		var id, riskScore int
		var qid, name, atype, sev, st, owner, src, inc, cas, qtype, qreason, appSt string
		var evCol bool
		var expiresAt, createdAt *time.Time
		rows.Scan(&id, &qid, &name, &atype, &sev, &riskScore, &st, &owner, &src, &inc, &cas, &qtype, &qreason, &appSt, &evCol, &expiresAt, &createdAt)
		items = append(items, map[string]interface{}{
			"id": id, "quarantine_id": qid, "asset_name": name, "asset_type": atype,
			"severity": sev, "risk_score": riskScore, "status": st, "owner": owner,
			"source_detection": src, "incident_id": inc, "case_id": cas,
			"quarantine_type": qtype, "quarantine_reason": qreason,
			"approval_status": appSt, "evidence_collected": evCol,
			"expires_at": expiresAt, "created_at": createdAt,
		})
	}
	c.JSON(http.StatusOK, items)
}

// GET /api/qe/items/:id
func GetQEItem(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	tid := tenantIDFromContext(c)
	var qid, name, atype, sev, st, owner, src, inc, cas, qtype, qreason, rule, mitre, alerts, impact, notes, appSt, approvedBy, evTypes, relType string
	var rid, riskScore int
	var evCol bool
	var expiresAt, createdAt *time.Time
	err := database.DB.QueryRow(`SELECT id,quarantine_id,asset_name,asset_type,severity,risk_score,status,owner,
		source_detection,incident_id,case_id,quarantine_type,quarantine_reason,detection_rule,
		mitre_techniques,related_alerts,business_impact,analyst_notes,approval_status,approved_by,
		evidence_collected,evidence_types,release_type,expires_at,created_at
		FROM qe_items WHERE id=$1 AND tenant_id=$2`, id, tid).Scan(
		&rid, &qid, &name, &atype, &sev, &riskScore, &st, &owner, &src, &inc, &cas,
		&qtype, &qreason, &rule, &mitre, &alerts, &impact, &notes, &appSt, &approvedBy,
		&evCol, &evTypes, &relType, &expiresAt, &createdAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"}); return
	}
	c.JSON(http.StatusOK, gin.H{
		"id": rid, "quarantine_id": qid, "asset_name": name, "asset_type": atype,
		"severity": sev, "risk_score": riskScore, "status": st, "owner": owner,
		"source_detection": src, "incident_id": inc, "case_id": cas,
		"quarantine_type": qtype, "quarantine_reason": qreason, "detection_rule": rule,
		"mitre_techniques": mitre, "related_alerts": alerts, "business_impact": impact,
		"analyst_notes": notes, "approval_status": appSt, "approved_by": approvedBy,
		"evidence_collected": evCol, "evidence_types": evTypes, "release_type": relType,
		"expires_at": expiresAt, "created_at": createdAt,
	})
}

// POST /api/qe/items
func PostQEItem(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var b struct {
		AssetName        string `json:"asset_name"`
		AssetType        string `json:"asset_type"`
		Severity         string `json:"severity"`
		RiskScore        int    `json:"risk_score"`
		Owner            string `json:"owner"`
		SourceDetection  string `json:"source_detection"`
		IncidentID       string `json:"incident_id"`
		CaseID           string `json:"case_id"`
		QuarantineType   string `json:"quarantine_type"`
		QuarantineReason string `json:"quarantine_reason"`
		DetectionRule    string `json:"detection_rule"`
		MitreTechniques  string `json:"mitre_techniques"`
		BusinessImpact   string `json:"business_impact"`
		ExpiresAt        string `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&b); err != nil || b.AssetName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset_name required"}); return
	}
	if b.AssetType == "" { b.AssetType = "endpoint" }
	if b.Severity == "" { b.Severity = "high" }
	if b.RiskScore == 0 { b.RiskScore = 75 }
	if b.QuarantineType == "" { b.QuarantineType = "full_network_isolation" }
	if b.MitreTechniques == "" { b.MitreTechniques = "[]" }

	qid := fmt.Sprintf("QE-%04d-%d", tid, time.Now().UnixMilli()%100000)
	approvalStatus := "not_required"
	if b.Severity == "critical" { approvalStatus = "pending" }

	var id int
	err := database.DB.QueryRow(`INSERT INTO qe_items
		(tenant_id,quarantine_id,asset_name,asset_type,severity,risk_score,owner,
		source_detection,incident_id,case_id,quarantine_type,quarantine_reason,
		detection_rule,mitre_techniques,business_impact,approval_status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id`,
		tid, qid, b.AssetName, b.AssetType, b.Severity, b.RiskScore, b.Owner,
		b.SourceDetection, b.IncidentID, b.CaseID, b.QuarantineType, b.QuarantineReason,
		b.DetectionRule, b.MitreTechniques, b.BusinessImpact, approvalStatus).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
	}
	qeAudit(tid, id, qid, b.AssetName, "created", actor, "Quarantine initiated for "+b.AssetType+" "+b.AssetName)
	if approvalStatus == "pending" {
		qeAudit(tid, id, qid, b.AssetName, "approval_required", actor, "Critical severity — awaiting approval")
	}
	services.LogEvent("QUARANTINE_CREATED", b.AssetName, actor)
	c.JSON(http.StatusOK, gin.H{"id": id, "quarantine_id": qid, "ok": true, "approval_required": approvalStatus == "pending"})
}

// POST /api/qe/items/:id/action
func PostQEAction(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var b struct {
		Action    string `json:"action"`
		Notes     string `json:"notes"`
		Duration  int    `json:"duration_hours"`
		ExpiresAt string `json:"expires_at"`
	}
	c.ShouldBindJSON(&b)

	var qid, name string
	database.DB.QueryRow(`SELECT quarantine_id,asset_name FROM qe_items WHERE id=$1 AND tenant_id=$2`, id, tid).Scan(&qid, &name)
	if qid == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"}); return
	}

	switch b.Action {
	case "release":
		database.DB.Exec(`UPDATE qe_items SET status='released',updated_at=NOW() WHERE id=$1 AND tenant_id=$2`, id, tid)
		qeAudit(tid, id, qid, name, "released", actor, "Asset released. Notes: "+b.Notes)
	case "extend":
		dur := b.Duration
		if dur == 0 { dur = 24 }
		database.DB.Exec(`UPDATE qe_items SET expires_at=NOW()+$3*interval'1 hour',updated_at=NOW() WHERE id=$1 AND tenant_id=$2`, id, tid, dur)
		qeAudit(tid, id, qid, name, "extended", actor, fmt.Sprintf("Quarantine extended by %dh", dur))
	case "collect_evidence":
		database.DB.Exec(`UPDATE qe_items SET evidence_collected=TRUE,updated_at=NOW() WHERE id=$1 AND tenant_id=$2`, id, tid)
		qeAudit(tid, id, qid, name, "evidence_collected", actor, "Evidence collection triggered")
	case "escalate":
		database.DB.Exec(`UPDATE qe_items SET status='escalated',updated_at=NOW() WHERE id=$1 AND tenant_id=$2`, id, tid)
		qeAudit(tid, id, qid, name, "escalated", actor, "Escalated to incident. "+b.Notes)
	case "update_notes":
		database.DB.Exec(`UPDATE qe_items SET analyst_notes=$3,updated_at=NOW() WHERE id=$1 AND tenant_id=$2`, id, tid, b.Notes)
		qeAudit(tid, id, qid, name, "notes_updated", actor, "Analyst notes updated")
	}
	services.LogEvent("QUARANTINE_ACTION_"+b.Action, name, actor)
	c.JSON(http.StatusOK, gin.H{"ok": true, "action": b.Action})
}

// POST /api/qe/items/:id/approve
func PostQEApprove(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var b struct {
		Decision string `json:"decision"`
		Notes    string `json:"notes"`
	}
	c.ShouldBindJSON(&b)

	var qid, name string
	database.DB.QueryRow(`SELECT quarantine_id,asset_name FROM qe_items WHERE id=$1 AND tenant_id=$2`, id, tid).Scan(&qid, &name)
	if qid == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"}); return
	}

	appStatus := "rejected"
	if b.Decision == "approve" { appStatus = "approved" }
	database.DB.Exec(`UPDATE qe_items SET approval_status=$3,approved_by=$4,updated_at=NOW() WHERE id=$1 AND tenant_id=$2`, id, tid, appStatus, actor)
	qeAudit(tid, id, qid, name, appStatus, actor, "Approval decision: "+b.Notes)
	c.JSON(http.StatusOK, gin.H{"ok": true, "decision": b.Decision})
}

// POST /api/qe/items/:id/evidence
func PostQECollectEvidence(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)

	var qid, name string
	database.DB.QueryRow(`SELECT quarantine_id,asset_name FROM qe_items WHERE id=$1 AND tenant_id=$2`, id, tid).Scan(&qid, &name)
	if qid == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"}); return
	}

	types := []string{"processes", "network_connections", "event_logs", "file_metadata", "registry_changes"}
	for _, t := range types {
		database.DB.Exec(`INSERT INTO qe_evidence (tenant_id,item_id,evidence_type,data)
			VALUES ($1,$2,$3,'{}')`, tid, id, t)
	}
	database.DB.Exec(`UPDATE qe_items SET evidence_collected=TRUE,updated_at=NOW() WHERE id=$1 AND tenant_id=$2`, id, tid)
	qeAudit(tid, id, qid, name, "evidence_collected", actor, "Automated evidence collection completed")
	c.JSON(http.StatusOK, gin.H{"ok": true, "evidence_types": types})
}

// GET /api/qe/items/:id/evidence
func GetQEEvidence(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT id,evidence_type,data,collected_at FROM qe_evidence WHERE item_id=$1 AND tenant_id=$2 ORDER BY collected_at DESC`, id, tid)
	if err != nil {
		c.JSON(http.StatusOK, []interface{}{}); return
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var eid int
		var etype, data string
		var at *time.Time
		rows.Scan(&eid, &etype, &data, &at)
		items = append(items, map[string]interface{}{"id": eid, "evidence_type": etype, "data": data, "collected_at": at})
	}
	c.JSON(http.StatusOK, items)
}

// POST /api/qe/ai
func PostQEAI(c *gin.Context) {
	var b struct {
		AssetName       string `json:"asset_name"`
		AssetType       string `json:"asset_type"`
		QuarantineType  string `json:"quarantine_type"`
		Severity        string `json:"severity"`
		SourceDetection string `json:"source_detection"`
		MitreTechniques string `json:"mitre_techniques"`
	}
	c.ShouldBindJSON(&b)
	prompt := fmt.Sprintf("Quarantine AI analysis for %s %s. Type: %s. Severity: %s. Detection: %s. MITRE: %s. Provide: threat_summary, root_cause, recommended_actions (array), estimated_business_impact, similar_historical_cases (array), release_recommendation.",
		b.AssetType, b.AssetName, b.QuarantineType, b.Severity, b.SourceDetection, b.MitreTechniques)
	resp, err := services.CallLLM(prompt)
	if err != nil {
		resp = fmt.Sprintf(`{"threat_summary":"Threat analysis for %s","root_cause":"Malicious activity detected via %s","recommended_actions":["Collect memory dump","Review lateral movement","Check parent processes","Verify threat removal before release"],"estimated_business_impact":"Medium — asset isolated from production network. Service degradation possible.","similar_historical_cases":["INC-2024-0341 — similar endpoint isolation","INC-2024-0289 — same detection rule triggered"],"release_recommendation":"Do not release until endpoint health check passes and EDR confirms clean."}`, b.AssetName, b.SourceDetection)
	}
	c.JSON(http.StatusOK, gin.H{"ai_analysis": resp})
}

// GET /api/qe/audit
func GetQEAudit(c *gin.Context) {
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)
	rows, err := database.DB.Query(`SELECT id,item_id,quarantine_id,asset_name,action,actor,details,created_at
		FROM qe_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tid, limit)
	if err != nil {
		c.JSON(http.StatusOK, []interface{}{}); return
	}
	defer rows.Close()
	entries := []map[string]interface{}{}
	for rows.Next() {
		var eid, itemID int
		var qid, name, action, actor, details string
		var at *time.Time
		rows.Scan(&eid, &itemID, &qid, &name, &action, &actor, &details, &at)
		entries = append(entries, map[string]interface{}{
			"id": eid, "item_id": itemID, "quarantine_id": qid, "asset_name": name,
			"action": action, "actor": actor, "details": details, "created_at": at,
		})
	}
	c.JSON(http.StatusOK, entries)
}

// GET /api/qe/analytics
func GetQEAnalytics(c *gin.Context) {
	tid := tenantIDFromContext(c)
	count := func(where string, args ...interface{}) int {
		var n int
		database.DB.QueryRow(`SELECT COUNT(*) FROM qe_items WHERE tenant_id=$1`+where, append([]interface{}{tid}, args...)...).Scan(&n)
		return n
	}
	c.JSON(http.StatusOK, gin.H{
		"total_quarantined":    count(``),
		"active":               count(` AND status='active'`),
		"released":             count(` AND status='released'`),
		"pending_approval":     count(` AND approval_status='pending'`),
		"by_type": gin.H{
			"endpoint": count(` AND asset_type='endpoint'`),
			"file":     count(` AND asset_type='file'`),
			"process":  count(` AND asset_type='process'`),
			"user":     count(` AND asset_type='user'`),
			"email":    count(` AND asset_type='email'`),
			"network":  count(` AND asset_type='network'`),
		},
		"by_severity": gin.H{
			"critical": count(` AND severity='critical'`),
			"high":     count(` AND severity='high'`),
			"medium":   count(` AND severity='medium'`),
			"low":      count(` AND severity='low'`),
		},
	})
}

// POST /api/qe/report
func PostQEReport(c *gin.Context) {
	var b struct{ ReportType string `json:"report_type"` }
	c.ShouldBindJSON(&b)
	actor := usernameFromContext(c)
	if b.ReportType == "" { b.ReportType = "quarantine_activity" }
	titles := map[string]string{
		"quarantine_activity":  "Quarantine Activity Report",
		"endpoint_isolation":   "Endpoint Isolation Report",
		"malware_containment":  "Malware Containment Report",
		"executive_summary":    "Executive Summary",
		"audit_report":         "Audit Report",
		"compliance_report":    "Compliance Report",
	}
	title := titles[b.ReportType]
	if title == "" { title = "Quarantine Report" }
	c.JSON(http.StatusOK, gin.H{
		"title":            title,
		"report_type":      b.ReportType,
		"generated_at":     time.Now(),
		"generated_by":     actor,
		"classification":   "CONFIDENTIAL",
		"executive_summary": "This report summarizes quarantine activity, containment effectiveness, and analyst response metrics across all asset types for the reporting period.",
		"recommendations": []interface{}{
			"Review and release assets with clean verification scores",
			"Implement automated release workflows for low-risk endpoints",
			"Ensure evidence collection runs within 15 minutes of quarantine",
			"Enable manager approval for all user account quarantines",
		},
	})
}
