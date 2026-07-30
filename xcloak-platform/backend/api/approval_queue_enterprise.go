package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/services"
)

func createAQTables() {
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS aq_requests (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		approval_id TEXT NOT NULL,
		request_type TEXT NOT NULL,
		action_category TEXT NOT NULL,
		severity TEXT DEFAULT 'high',
		risk_score INTEGER DEFAULT 50,
		description TEXT,
		requested_action TEXT NOT NULL,
		target_asset TEXT,
		target_user TEXT,
		requester TEXT,
		current_approver TEXT,
		status TEXT DEFAULT 'pending',
		incident_id TEXT,
		case_id TEXT,
		alert_id TEXT,
		mitre_technique TEXT,
		business_impact TEXT,
		risk_level TEXT DEFAULT 'high',
		policy TEXT DEFAULT 'manager_approval',
		is_emergency BOOLEAN DEFAULT false,
		due_at TIMESTAMPTZ,
		approved_at TIMESTAMPTZ,
		executed_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ DEFAULT NOW(),
		updated_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	// Several nullable TEXT columns above have no DEFAULT, so any INSERT
	// that omits one (OT/ICS's direct escalate_emergency/block_network_path
	// writes, and the demo seeder, both do) leaves it NULL. Every handler
	// in this file scans these into plain Go `string` fields, and scanning
	// SQL NULL into a non-nullable string errors — silently dropping the
	// whole row via the `if rows.Scan(...) == nil` pattern used throughout.
	// Confirmed live: GetAQQueue returned an empty list despite 10 real
	// rows existing, because every single one had at least one NULL
	// column. Fix at the schema level rather than adding COALESCE to every
	// SELECT in this 700-line file.
	for _, col := range []string{"description", "target_asset", "target_user", "requester", "current_approver", "incident_id", "case_id", "alert_id", "mitre_technique", "business_impact"} {
		database.DB.Exec(fmt.Sprintf(`ALTER TABLE aq_requests ALTER COLUMN %s SET DEFAULT ''`, col))
		database.DB.Exec(fmt.Sprintf(`UPDATE aq_requests SET %s='' WHERE %s IS NULL`, col, col))
	}
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS aq_decisions (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		request_id INTEGER NOT NULL,
		decision TEXT NOT NULL,
		actor TEXT,
		notes TEXT,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS aq_policies (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		name TEXT,
		action_type TEXT NOT NULL,
		asset_criticality TEXT DEFAULT 'any',
		policy TEXT DEFAULT 'manager_approval',
		approvers TEXT,
		auto_conditions TEXT,
		enabled BOOLEAN DEFAULT true,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS aq_comments (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		request_id INTEGER NOT NULL,
		author TEXT,
		content TEXT,
		comment_type TEXT DEFAULT 'note',
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS aq_audit (
		id SERIAL PRIMARY KEY,
		tenant_id INTEGER NOT NULL,
		request_id INTEGER,
		approval_id TEXT,
		actor TEXT,
		action TEXT,
		details TEXT,
		ip_address TEXT,
		created_at TIMESTAMPTZ DEFAULT NOW()
	)`)
	// Same NULL-scan defense as aq_requests above, applied to every other
	// nullable TEXT column in this file's tables — aq_policies.auto_conditions
	// (every seeded/PostAQPolicy-created row that doesn't set it) and
	// aq_audit.ip_address (every INSERT in this codebase omits it — no
	// caller ever captures a real client IP) both silently broke their
	// GET handlers exactly like aq_requests did.
	for _, col := range []string{"name", "approvers", "auto_conditions"} {
		database.DB.Exec(fmt.Sprintf(`ALTER TABLE aq_policies ALTER COLUMN %s SET DEFAULT ''`, col))
		database.DB.Exec(fmt.Sprintf(`UPDATE aq_policies SET %s='' WHERE %s IS NULL`, col, col))
	}
	for _, col := range []string{"author", "content"} {
		database.DB.Exec(fmt.Sprintf(`ALTER TABLE aq_comments ALTER COLUMN %s SET DEFAULT ''`, col))
		database.DB.Exec(fmt.Sprintf(`UPDATE aq_comments SET %s='' WHERE %s IS NULL`, col, col))
	}
	for _, col := range []string{"approval_id", "actor", "action", "details", "ip_address"} {
		database.DB.Exec(fmt.Sprintf(`ALTER TABLE aq_audit ALTER COLUMN %s SET DEFAULT ''`, col))
		database.DB.Exec(fmt.Sprintf(`UPDATE aq_audit SET %s='' WHERE %s IS NULL`, col, col))
	}
}

// GetAQDashboard — GET /api/aq/dashboard
func GetAQDashboard(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	type Stats struct {
		Pending         int     `json:"pending"`
		Approved        int     `json:"approved"`
		Rejected        int     `json:"rejected"`
		Expired         int     `json:"expired"`
		HighRisk        int     `json:"high_risk"`
		Emergency       int     `json:"emergency"`
		AvgApprovalTime float64 `json:"avg_approval_time_min"`
		SLACompliance   float64 `json:"sla_compliance"`
		TotalRequests   int     `json:"total_requests"`
		AutoApproved    int     `json:"auto_approved"`
	}
	var s Stats
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND status='pending'`, tid).Scan(&s.Pending)
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND status='approved'`, tid).Scan(&s.Approved)
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND status='rejected'`, tid).Scan(&s.Rejected)
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND status='expired'`, tid).Scan(&s.Expired)
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND risk_level IN ('critical','high')`, tid).Scan(&s.HighRisk)
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND is_emergency=true`, tid).Scan(&s.Emergency)
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1`, tid).Scan(&s.TotalRequests)
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND policy='automatic'`, tid).Scan(&s.AutoApproved)
	database.DB.QueryRow(`SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (approved_at-created_at))/60),0) FROM aq_requests WHERE tenant_id=$1 AND status='approved'`, tid).Scan(&s.AvgApprovalTime)
	database.DB.QueryRow(`
		SELECT CASE WHEN COUNT(*) FILTER (WHERE status IN ('approved','rejected')) > 0
			THEN 100.0 * COUNT(*) FILTER (WHERE status='approved' AND approved_at <= due_at) / COUNT(*) FILTER (WHERE status IN ('approved','rejected'))
			ELSE 100.0 END
		FROM aq_requests WHERE tenant_id=$1`, tid).Scan(&s.SLACompliance)

	type categoryRow struct {
		Category string `json:"category"`
		Count    int    `json:"count"`
	}
	byCategory := []categoryRow{}
	cRows, _ := database.DB.Query(`SELECT action_category, COUNT(*) FROM aq_requests WHERE tenant_id=$1 GROUP BY action_category ORDER BY COUNT(*) DESC`, tid)
	if cRows != nil {
		defer cRows.Close()
		for cRows.Next() {
			var r categoryRow
			if cRows.Scan(&r.Category, &r.Count) == nil {
				byCategory = append(byCategory, r)
			}
		}
	}

	type policyRow struct {
		Policy string `json:"policy"`
		Count  int    `json:"count"`
	}
	byPolicy := []policyRow{}
	pRows, _ := database.DB.Query(`SELECT policy, COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND status='approved' GROUP BY policy ORDER BY COUNT(*) DESC`, tid)
	if pRows != nil {
		defer pRows.Close()
		for pRows.Next() {
			var r policyRow
			if pRows.Scan(&r.Policy, &r.Count) == nil {
				byPolicy = append(byPolicy, r)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"pending":               s.Pending,
		"approved":              s.Approved,
		"rejected":              s.Rejected,
		"expired":               s.Expired,
		"high_risk":             s.HighRisk,
		"emergency":             s.Emergency,
		"avg_approval_time_min": s.AvgApprovalTime,
		"sla_compliance":        s.SLACompliance,
		"total_requests":        s.TotalRequests,
		"auto_approved":         s.AutoApproved,
		"by_category":           byCategory,
		"by_policy":             byPolicy,
	})
}

// GetAQQueue — GET /api/aq/queue
func GetAQQueue(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 50)
	q := `SELECT id,approval_id,request_type,action_category,severity,risk_score,requested_action,target_asset,target_user,requester,current_approver,status,incident_id,case_id,risk_level,policy,is_emergency,due_at,created_at,updated_at
		FROM aq_requests WHERE tenant_id=$1`
	args := []interface{}{tid}
	i := 2
	if v := c.Query("status"); v != "" {
		q += fmt.Sprintf(" AND status=$%d", i)
		args = append(args, v)
		i++
	}
	if v := c.Query("severity"); v != "" {
		q += fmt.Sprintf(" AND severity=$%d", i)
		args = append(args, v)
		i++
	}
	if v := c.Query("category"); v != "" {
		q += fmt.Sprintf(" AND action_category=$%d", i)
		args = append(args, v)
		i++
	}
	q += fmt.Sprintf(" ORDER BY CASE WHEN status='pending' THEN 0 ELSE 1 END, risk_score DESC, created_at DESC LIMIT $%d", i)
	args = append(args, limit)
	rows, _ := database.DB.Query(q, args...)
	type Req struct {
		ID              int     `json:"id"`
		ApprovalID      string  `json:"approval_id"`
		RequestType     string  `json:"request_type"`
		ActionCategory  string  `json:"action_category"`
		Severity        string  `json:"severity"`
		RiskScore       int     `json:"risk_score"`
		RequestedAction string  `json:"requested_action"`
		TargetAsset     string  `json:"target_asset"`
		TargetUser      string  `json:"target_user"`
		Requester       string  `json:"requester"`
		CurrentApprover string  `json:"current_approver"`
		Status          string  `json:"status"`
		IncidentID      string  `json:"incident_id"`
		CaseID          string  `json:"case_id"`
		RiskLevel       string  `json:"risk_level"`
		Policy          string  `json:"policy"`
		IsEmergency     bool    `json:"is_emergency"`
		DueAt           *string `json:"due_at"`
		CreatedAt       string  `json:"created_at"`
		UpdatedAt       string  `json:"updated_at"`
	}
	list := []Req{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r Req
			if rows.Scan(&r.ID, &r.ApprovalID, &r.RequestType, &r.ActionCategory, &r.Severity, &r.RiskScore, &r.RequestedAction, &r.TargetAsset, &r.TargetUser, &r.Requester, &r.CurrentApprover, &r.Status, &r.IncidentID, &r.CaseID, &r.RiskLevel, &r.Policy, &r.IsEmergency, &r.DueAt, &r.CreatedAt, &r.UpdatedAt) == nil {
				list = append(list, r)
			}
		}
	}
	if list == nil {
		list = []Req{}
	}
	c.JSON(http.StatusOK, list)
}

// PostAQRequest — POST /api/aq/queue
func PostAQRequest(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	var body struct {
		RequestType     string `json:"request_type"`
		ActionCategory  string `json:"action_category"`
		Severity        string `json:"severity"`
		RiskScore       int    `json:"risk_score"`
		Description     string `json:"description"`
		RequestedAction string `json:"requested_action"`
		TargetAsset     string `json:"target_asset"`
		TargetUser      string `json:"target_user"`
		IncidentID      string `json:"incident_id"`
		CaseID          string `json:"case_id"`
		AlertID         string `json:"alert_id"`
		MITRETechnique  string `json:"mitre_technique"`
		BusinessImpact  string `json:"business_impact"`
		RiskLevel       string `json:"risk_level"`
		Policy          string `json:"policy"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.RequestedAction == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "requested_action required"})
		return
	}
	requester := usernameFromContext(c)
	approvalID := fmt.Sprintf("AQ-%d-%06d", time.Now().Year(), time.Now().UnixNano()%1000000)
	if body.Severity == "" {
		body.Severity = "high"
	}
	if body.Policy == "" {
		body.Policy = "manager_approval"
	}
	if body.RiskLevel == "" {
		body.RiskLevel = "high"
	}
	due := time.Now().Add(30 * time.Minute)
	var id int
	database.DB.QueryRow(`INSERT INTO aq_requests (tenant_id,approval_id,request_type,action_category,severity,risk_score,description,requested_action,target_asset,target_user,requester,incident_id,case_id,alert_id,mitre_technique,business_impact,risk_level,policy,due_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) RETURNING id`,
		tid, approvalID, body.RequestType, body.ActionCategory, body.Severity, body.RiskScore, body.Description, body.RequestedAction, body.TargetAsset, body.TargetUser, requester, body.IncidentID, body.CaseID, body.AlertID, body.MITRETechnique, body.BusinessImpact, body.RiskLevel, body.Policy, due).Scan(&id)
	database.DB.Exec(`INSERT INTO aq_audit (tenant_id,request_id,approval_id,actor,action,details) VALUES($1,$2,$3,$4,'created','Request submitted via API')`, tid, id, approvalID, requester)
	c.JSON(http.StatusOK, gin.H{"id": id, "approval_id": approvalID, "ok": true})
}

// GetAQRequestByID — GET /api/aq/queue/:id
func GetAQRequestByID(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	rid, _ := strconv.Atoi(c.Param("id"))
	type Req struct {
		ID              int     `json:"id"`
		ApprovalID      string  `json:"approval_id"`
		RequestType     string  `json:"request_type"`
		ActionCategory  string  `json:"action_category"`
		Severity        string  `json:"severity"`
		RiskScore       int     `json:"risk_score"`
		Description     string  `json:"description"`
		RequestedAction string  `json:"requested_action"`
		TargetAsset     string  `json:"target_asset"`
		TargetUser      string  `json:"target_user"`
		Requester       string  `json:"requester"`
		CurrentApprover string  `json:"current_approver"`
		Status          string  `json:"status"`
		IncidentID      string  `json:"incident_id"`
		CaseID          string  `json:"case_id"`
		AlertID         string  `json:"alert_id"`
		MITRETechnique  string  `json:"mitre_technique"`
		BusinessImpact  string  `json:"business_impact"`
		RiskLevel       string  `json:"risk_level"`
		Policy          string  `json:"policy"`
		IsEmergency     bool    `json:"is_emergency"`
		DueAt           *string `json:"due_at"`
		ApprovedAt      *string `json:"approved_at"`
		ExecutedAt      *string `json:"executed_at"`
		CreatedAt       string  `json:"created_at"`
		UpdatedAt       string  `json:"updated_at"`
	}
	var r Req
	err := database.DB.QueryRow(`SELECT id,approval_id,request_type,action_category,severity,risk_score,description,requested_action,target_asset,target_user,requester,current_approver,status,incident_id,case_id,alert_id,mitre_technique,business_impact,risk_level,policy,is_emergency,due_at,approved_at,executed_at,created_at,updated_at
		FROM aq_requests WHERE id=$1 AND tenant_id=$2`, rid, tid).Scan(&r.ID, &r.ApprovalID, &r.RequestType, &r.ActionCategory, &r.Severity, &r.RiskScore, &r.Description, &r.RequestedAction, &r.TargetAsset, &r.TargetUser, &r.Requester, &r.CurrentApprover, &r.Status, &r.IncidentID, &r.CaseID, &r.AlertID, &r.MITRETechnique, &r.BusinessImpact, &r.RiskLevel, &r.Policy, &r.IsEmergency, &r.DueAt, &r.ApprovedAt, &r.ExecutedAt, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, r)
}

// PostAQDecision — POST /api/aq/queue/:id/decision
func PostAQDecision(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	rid, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		Decision string `json:"decision"`
		Notes    string `json:"notes"`
	}
	c.ShouldBindJSON(&body)
	actor := usernameFromContext(c)
	var aid string
	database.DB.QueryRow(`SELECT approval_id FROM aq_requests WHERE id=$1 AND tenant_id=$2`, rid, tid).Scan(&aid)
	newStatus := body.Decision
	if body.Decision == "approve" {
		newStatus = "approved"
	}
	if body.Decision == "reject" {
		newStatus = "rejected"
	}
	now := time.Now()
	if newStatus == "approved" {
		database.DB.Exec(`UPDATE aq_requests SET status=$1, current_approver=$2, approved_at=$3, updated_at=NOW() WHERE id=$4 AND tenant_id=$5`, newStatus, actor, now, rid, tid)
	} else {
		database.DB.Exec(`UPDATE aq_requests SET status=$1, current_approver=$2, updated_at=NOW() WHERE id=$3 AND tenant_id=$4`, newStatus, actor, rid, tid)
	}
	database.DB.Exec(`INSERT INTO aq_decisions (tenant_id,request_id,decision,actor,notes) VALUES($1,$2,$3,$4,$5)`, tid, rid, body.Decision, actor, body.Notes)
	database.DB.Exec(`INSERT INTO aq_audit (tenant_id,request_id,approval_id,actor,action,details) VALUES($1,$2,$3,$4,$5,$6)`, tid, rid, aid, actor, body.Decision, body.Notes)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// PostAQDelegate — POST /api/aq/queue/:id/delegate
func PostAQDelegate(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	rid, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		Delegatee string `json:"delegatee"`
		Notes     string `json:"notes"`
	}
	c.ShouldBindJSON(&body)
	actor := usernameFromContext(c)
	var aid string
	database.DB.QueryRow(`SELECT approval_id FROM aq_requests WHERE id=$1 AND tenant_id=$2`, rid, tid).Scan(&aid)
	database.DB.Exec(`UPDATE aq_requests SET current_approver=$1, status='delegated', updated_at=NOW() WHERE id=$2 AND tenant_id=$3`, body.Delegatee, rid, tid)
	database.DB.Exec(`INSERT INTO aq_audit (tenant_id,request_id,approval_id,actor,action,details) VALUES($1,$2,$3,$4,'delegated',$5)`, tid, rid, aid, actor, fmt.Sprintf("Delegated to %s: %s", body.Delegatee, body.Notes))
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// PostAQEmergency — POST /api/aq/queue/:id/emergency
func PostAQEmergency(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	rid, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		Justification string `json:"justification"`
	}
	c.ShouldBindJSON(&body)
	actor := usernameFromContext(c)
	var aid string
	database.DB.QueryRow(`SELECT approval_id FROM aq_requests WHERE id=$1 AND tenant_id=$2`, rid, tid).Scan(&aid)
	database.DB.Exec(`UPDATE aq_requests SET status='approved', is_emergency=true, approved_at=NOW(), current_approver=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3`, actor, rid, tid)
	database.DB.Exec(`INSERT INTO aq_decisions (tenant_id,request_id,decision,actor,notes) VALUES($1,$2,'emergency_override',$3,$4)`, tid, rid, actor, body.Justification)
	database.DB.Exec(`INSERT INTO aq_audit (tenant_id,request_id,approval_id,actor,action,details) VALUES($1,$2,$3,$4,'emergency_override',$5)`, tid, rid, aid, actor, "BREAK GLASS: "+body.Justification)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// GetAQComments — GET /api/aq/queue/:id/comments
func GetAQComments(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	rid, _ := strconv.Atoi(c.Param("id"))
	rows, _ := database.DB.Query(`SELECT id,author,content,comment_type,created_at FROM aq_comments WHERE request_id=$1 AND tenant_id=$2 ORDER BY created_at`, rid, tid)
	type Comment struct {
		ID          int    `json:"id"`
		Author      string `json:"author"`
		Content     string `json:"content"`
		CommentType string `json:"comment_type"`
		CreatedAt   string `json:"created_at"`
	}
	list := []Comment{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var cm Comment
			if rows.Scan(&cm.ID, &cm.Author, &cm.Content, &cm.CommentType, &cm.CreatedAt) == nil {
				list = append(list, cm)
			}
		}
	}
	if list == nil {
		list = []Comment{}
	}
	c.JSON(http.StatusOK, list)
}

// PostAQComment — POST /api/aq/queue/:id/comments
func PostAQComment(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	rid, _ := strconv.Atoi(c.Param("id"))
	var body struct {
		Content     string `json:"content"`
		CommentType string `json:"comment_type"`
	}
	c.ShouldBindJSON(&body)
	author := usernameFromContext(c)
	if body.CommentType == "" {
		body.CommentType = "note"
	}
	var id int
	database.DB.QueryRow(`INSERT INTO aq_comments (tenant_id,request_id,author,content,comment_type) VALUES($1,$2,$3,$4,$5) RETURNING id`, tid, rid, author, body.Content, body.CommentType).Scan(&id)
	var aid string
	database.DB.QueryRow(`SELECT approval_id FROM aq_requests WHERE id=$1 AND tenant_id=$2`, rid, tid).Scan(&aid)
	database.DB.Exec(`INSERT INTO aq_audit (tenant_id,request_id,approval_id,actor,action,details) VALUES($1,$2,$3,$4,'commented',$5)`, tid, rid, aid, author, body.Content)
	c.JSON(http.StatusOK, gin.H{"id": id, "ok": true})
}

// GetAQTimeline — GET /api/aq/queue/:id/timeline
func GetAQTimeline(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	rid, _ := strconv.Atoi(c.Param("id"))
	rows, _ := database.DB.Query(`SELECT id,actor,action,details,created_at FROM aq_audit WHERE request_id=$1 AND tenant_id=$2 ORDER BY created_at`, rid, tid)
	type Entry struct {
		ID        int    `json:"id"`
		Actor     string `json:"actor"`
		Action    string `json:"action"`
		Details   string `json:"details"`
		CreatedAt string `json:"created_at"`
	}
	list := []Entry{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e Entry
			if rows.Scan(&e.ID, &e.Actor, &e.Action, &e.Details, &e.CreatedAt) == nil {
				list = append(list, e)
			}
		}
	}
	if list == nil {
		list = []Entry{}
	}
	c.JSON(http.StatusOK, list)
}

// GetAQEvidence — GET /api/aq/queue/:id/evidence
//
// Backed entirely by the aq_requests row's own incident_id/alert_id/
// target_asset/target_user fields — there is no real per-request process-
// tree or security-event-log linkage anywhere in this schema, so those two
// concepts (previously fully fabricated) are dropped rather than faked.
func GetAQEvidence(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	rid, _ := strconv.Atoi(c.Param("id"))
	var incidentIDStr, alertIDStr, targetAsset, targetUser string
	if err := database.DB.QueryRow(`SELECT incident_id,alert_id,target_asset,target_user FROM aq_requests WHERE id=$1 AND tenant_id=$2`, rid, tid).
		Scan(&incidentIDStr, &alertIDStr, &targetAsset, &targetUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	resp := gin.H{}

	if incidentID, err := strconv.Atoi(incidentIDStr); err == nil {
		type Incident struct {
			ID       int    `json:"id"`
			Title    string `json:"title"`
			Severity string `json:"severity"`
			Status   string `json:"status"`
			AgentID  int    `json:"-"`
		}
		var inc Incident
		if database.DB.QueryRow(`SELECT id,title,severity,status,COALESCE(agent_id,0) FROM incidents WHERE id=$1 AND tenant_id=$2`, incidentID, tid).
			Scan(&inc.ID, &inc.Title, &inc.Severity, &inc.Status, &inc.AgentID) == nil {
			resp["incident"] = inc

			type AlertRow struct {
				ID        int    `json:"id"`
				Title     string `json:"title"`
				Severity  string `json:"severity"`
				CreatedAt string `json:"created_at"`
			}
			alerts := []AlertRow{}
			if aid, err := strconv.Atoi(alertIDStr); err == nil {
				var a AlertRow
				if database.DB.QueryRow(`SELECT id,rule_name,severity,created_at FROM alerts WHERE id=$1 AND tenant_id=$2`, aid, tid).
					Scan(&a.ID, &a.Title, &a.Severity, &a.CreatedAt) == nil {
					alerts = append(alerts, a)
				}
			} else if inc.AgentID > 0 {
				rows, _ := database.DB.Query(`SELECT id,rule_name,severity,created_at FROM alerts WHERE tenant_id=$1 AND agent_id=$2 ORDER BY created_at DESC LIMIT 5`, tid, inc.AgentID)
				if rows != nil {
					defer rows.Close()
					for rows.Next() {
						var a AlertRow
						if rows.Scan(&a.ID, &a.Title, &a.Severity, &a.CreatedAt) == nil {
							alerts = append(alerts, a)
						}
					}
				}
			}
			resp["related_alerts"] = alerts
		}
	}

	needle := targetAsset
	if needle == "" {
		needle = targetUser
	}
	if needle != "" {
		type TI struct {
			Indicator   string     `json:"indicator"`
			Type        string     `json:"type"`
			Severity    string     `json:"severity"`
			Description string     `json:"description"`
			HitCount    int        `json:"hit_count"`
			LastSeen    *time.Time `json:"last_seen"`
		}
		var ti TI
		if database.DB.QueryRow(`SELECT indicator,type,severity,description,hit_count,last_seen FROM iocs WHERE tenant_id=$1 AND indicator ILIKE $2 AND enabled=true LIMIT 1`, tid, "%"+needle+"%").
			Scan(&ti.Indicator, &ti.Type, &ti.Severity, &ti.Description, &ti.HitCount, &ti.LastSeen) == nil {
			resp["threat_intel"] = ti
		}
	}

	c.JSON(http.StatusOK, resp)
}

// GetAQPolicies — GET /api/aq/policies
func GetAQPolicies(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT id,name,action_type,asset_criticality,policy,approvers,auto_conditions,enabled,created_at FROM aq_policies WHERE tenant_id=$1 ORDER BY created_at`, tid)
	type Policy struct {
		ID               int    `json:"id"`
		Name             string `json:"name"`
		ActionType       string `json:"action_type"`
		AssetCriticality string `json:"asset_criticality"`
		Policy           string `json:"policy"`
		Approvers        string `json:"approvers"`
		AutoConditions   string `json:"auto_conditions"`
		Enabled          bool   `json:"enabled"`
		CreatedAt        string `json:"created_at"`
	}
	list := []Policy{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var p Policy
			if rows.Scan(&p.ID, &p.Name, &p.ActionType, &p.AssetCriticality, &p.Policy, &p.Approvers, &p.AutoConditions, &p.Enabled, &p.CreatedAt) == nil {
				list = append(list, p)
			}
		}
	}
	if list == nil {
		list = []Policy{}
	}
	c.JSON(http.StatusOK, list)
}

// PostAQPolicy — POST /api/aq/policies
func PostAQPolicy(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Name             string `json:"name"`
		ActionType       string `json:"action_type"`
		AssetCriticality string `json:"asset_criticality"`
		Policy           string `json:"policy"`
		Approvers        string `json:"approvers"`
		AutoConditions   string `json:"auto_conditions"`
	}
	c.ShouldBindJSON(&body)
	if body.AssetCriticality == "" {
		body.AssetCriticality = "any"
	}
	if body.Policy == "" {
		body.Policy = "manager_approval"
	}
	var id int
	database.DB.QueryRow(`INSERT INTO aq_policies (tenant_id,name,action_type,asset_criticality,policy,approvers,auto_conditions) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		tid, body.Name, body.ActionType, body.AssetCriticality, body.Policy, body.Approvers, body.AutoConditions).Scan(&id)
	c.JSON(http.StatusOK, gin.H{"id": id, "ok": true})
}

// PatchAQPolicy — PATCH /api/aq/policies/:pid
func PatchAQPolicy(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	pid, _ := strconv.Atoi(c.Param("pid"))
	var body map[string]interface{}
	c.ShouldBindJSON(&body)
	fields := []string{}
	vals := []interface{}{}
	i := 1
	for _, k := range []string{"name", "policy", "approvers", "auto_conditions", "enabled", "asset_criticality"} {
		if v, ok := body[k]; ok {
			fields = append(fields, fmt.Sprintf("%s=$%d", k, i))
			vals = append(vals, v)
			i++
		}
	}
	if len(fields) > 0 {
		vals = append(vals, pid, tid)
		database.DB.Exec(fmt.Sprintf(`UPDATE aq_policies SET %s WHERE id=$%d AND tenant_id=$%d`, strings.Join(fields, ","), i, i+1), vals...)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DeleteAQPolicy — DELETE /api/aq/policies/:pid
func DeleteAQPolicy(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	pid, _ := strconv.Atoi(c.Param("pid"))
	database.DB.Exec(`DELETE FROM aq_policies WHERE id=$1 AND tenant_id=$2`, pid, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// GetAQMatrix — GET /api/aq/matrix
func GetAQMatrix(c *gin.Context) {
	c.JSON(http.StatusOK, []interface{}{
		map[string]interface{}{"action": "Kill malware process on workstation", "category": "endpoint", "asset_criticality": "low", "requirement": "automatic", "approvers": "auto", "risk": "low"},
		map[string]interface{}{"action": "Isolate workstation", "category": "endpoint", "asset_criticality": "medium", "requirement": "soc_lead", "approvers": "SOC Team Lead", "risk": "medium"},
		map[string]interface{}{"action": "Isolate server", "category": "endpoint", "asset_criticality": "high", "requirement": "manager_approval", "approvers": "SOC Manager", "risk": "high"},
		map[string]interface{}{"action": "Disable standard user account", "category": "identity", "asset_criticality": "low", "requirement": "soc_lead", "approvers": "SOC Team Lead", "risk": "medium"},
		map[string]interface{}{"action": "Disable Domain Admin account", "category": "identity", "asset_criticality": "high", "requirement": "dual_approval", "approvers": "SOC Manager + Identity Team", "risk": "critical"},
		map[string]interface{}{"action": "Disable Executive account", "category": "identity", "asset_criticality": "critical", "requirement": "executive_approval", "approvers": "CISO + HR", "risk": "critical"},
		map[string]interface{}{"action": "Block IP at firewall", "category": "network", "asset_criticality": "any", "requirement": "automatic", "approvers": "auto", "risk": "low"},
		map[string]interface{}{"action": "Update perimeter firewall rules", "category": "network", "asset_criticality": "any", "requirement": "soc_lead", "approvers": "SOC Team Lead + Network Team", "risk": "high"},
		map[string]interface{}{"action": "Stop production database", "category": "endpoint", "asset_criticality": "critical", "requirement": "dual_approval", "approvers": "SOC Manager + App Owner", "risk": "critical"},
		map[string]interface{}{"action": "Delete all phishing emails from mailboxes", "category": "email", "asset_criticality": "any", "requirement": "manager_approval", "approvers": "SOC Manager", "risk": "high"},
		map[string]interface{}{"action": "Quarantine mailbox", "category": "email", "asset_criticality": "any", "requirement": "soc_lead", "approvers": "SOC Team Lead", "risk": "medium"},
		map[string]interface{}{"action": "Stop EC2 instance", "category": "cloud", "asset_criticality": "medium", "requirement": "soc_lead", "approvers": "SOC Team Lead + Cloud Team", "risk": "high"},
		map[string]interface{}{"action": "Stop production EC2 instance", "category": "cloud", "asset_criticality": "critical", "requirement": "dual_approval", "approvers": "SOC Manager + App Owner", "risk": "critical"},
		map[string]interface{}{"action": "Revoke AWS IAM credentials", "category": "cloud", "asset_criticality": "any", "requirement": "manager_approval", "approvers": "SOC Manager + Cloud Security", "risk": "high"},
		map[string]interface{}{"action": "Reset password (standard user)", "category": "identity", "asset_criticality": "any", "requirement": "automatic", "approvers": "auto", "risk": "low"},
		map[string]interface{}{"action": "Reset Domain Controller password", "category": "active_directory", "asset_criticality": "critical", "requirement": "executive_approval", "approvers": "CISO + IT Director", "risk": "critical"},
	})
}

// GetAQAnalytics — GET /api/aq/analytics
func GetAQAnalytics(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	var total, pending, approved, rejected, emergency, autoApproved int
	var avgTime float64
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND status='pending'`, tid).Scan(&pending)
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND status='approved'`, tid).Scan(&approved)
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND status='rejected'`, tid).Scan(&rejected)
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND is_emergency=true`, tid).Scan(&emergency)
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND policy='automatic'`, tid).Scan(&autoApproved)
	database.DB.QueryRow(`SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (approved_at-created_at))/60),0) FROM aq_requests WHERE tenant_id=$1 AND status='approved'`, tid).Scan(&avgTime)
	var slaViolations int
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND status='approved' AND approved_at > due_at`, tid).Scan(&slaViolations)

	type catRow struct {
		Category string `json:"category"`
		Count    int    `json:"count"`
		Auto     int    `json:"auto"`
		Approved int    `json:"approved"`
		Rejected int    `json:"rejected"`
	}
	byCategory := []catRow{}
	cRows, _ := database.DB.Query(`
		SELECT action_category, COUNT(*), COUNT(*) FILTER (WHERE policy='automatic'), COUNT(*) FILTER (WHERE status='approved'), COUNT(*) FILTER (WHERE status='rejected')
		FROM aq_requests WHERE tenant_id=$1 GROUP BY action_category ORDER BY COUNT(*) DESC`, tid)
	if cRows != nil {
		defer cRows.Close()
		for cRows.Next() {
			var r catRow
			if cRows.Scan(&r.Category, &r.Count, &r.Auto, &r.Approved, &r.Rejected) == nil {
				byCategory = append(byCategory, r)
			}
		}
	}

	type approverRow struct {
		Approver   string  `json:"approver"`
		Approved   int     `json:"approved"`
		AvgTimeMin float64 `json:"avg_time_min"`
	}
	byApprover := []approverRow{}
	aRows, _ := database.DB.Query(`
		SELECT current_approver, COUNT(*), COALESCE(AVG(EXTRACT(EPOCH FROM (approved_at-created_at))/60),0)
		FROM aq_requests WHERE tenant_id=$1 AND status='approved' AND current_approver != '' GROUP BY current_approver ORDER BY COUNT(*) DESC LIMIT 10`, tid)
	if aRows != nil {
		defer aRows.Close()
		for aRows.Next() {
			var r approverRow
			if aRows.Scan(&r.Approver, &r.Approved, &r.AvgTimeMin) == nil {
				byApprover = append(byApprover, r)
			}
		}
	}

	type trendRow struct {
		Date     string `json:"date"`
		Requests int    `json:"requests"`
		Approved int    `json:"approved"`
		Rejected int    `json:"rejected"`
	}
	trend := []trendRow{}
	for i := 7; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i)
		dayStr := d.Format("2006-01-02")
		var reqs, appr, rej int
		database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND DATE(created_at)=$2`, tid, dayStr).Scan(&reqs)
		database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND DATE(created_at)=$2 AND status='approved'`, tid, dayStr).Scan(&appr)
		database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND DATE(created_at)=$2 AND status='rejected'`, tid, dayStr).Scan(&rej)
		trend = append(trend, trendRow{Date: d.Format("01-02"), Requests: reqs, Approved: appr, Rejected: rej})
	}

	c.JSON(http.StatusOK, gin.H{
		"avg_approval_time_min": avgTime,
		"total":                 total,
		"pending":               pending,
		"approved":              approved,
		"rejected":              rejected,
		"sla_violations":        slaViolations,
		"emergency_requests":    emergency,
		"auto_approved":         autoApproved,
		"by_category":           byCategory,
		"by_approver":           byApprover,
		"trend":                 trend,
	})
}

// GetAQAudit — GET /api/aq/audit
func GetAQAudit(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT id,request_id,approval_id,actor,action,details,ip_address,created_at FROM aq_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100`, tid)
	type Entry struct {
		ID         int    `json:"id"`
		RequestID  int    `json:"request_id"`
		ApprovalID string `json:"approval_id"`
		Actor      string `json:"actor"`
		Action     string `json:"action"`
		Details    string `json:"details"`
		IPAddress  string `json:"ip_address"`
		CreatedAt  string `json:"created_at"`
	}
	list := []Entry{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e Entry
			if rows.Scan(&e.ID, &e.RequestID, &e.ApprovalID, &e.Actor, &e.Action, &e.Details, &e.IPAddress, &e.CreatedAt) == nil {
				list = append(list, e)
			}
		}
	}
	if list == nil {
		list = []Entry{}
	}
	c.JSON(http.StatusOK, list)
}

// GetAQApprovers — GET /api/aq/approvers
func GetAQApprovers(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT username, role, is_active FROM users WHERE tenant_id=$1 ORDER BY username`, tid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Approver struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Role      string `json:"role"`
		Available bool   `json:"available"`
	}
	list := []Approver{}
	for rows.Next() {
		var a Approver
		if rows.Scan(&a.ID, &a.Role, &a.Available) == nil {
			a.Name = a.ID
			list = append(list, a)
		}
	}
	c.JSON(http.StatusOK, list)
}

// PostAQAI — POST /api/aq/ai
func PostAQAI(c *gin.Context) {
	var body struct {
		Mode    string `json:"mode"`
		Context string `json:"context"`
		Action  string `json:"action"`
		Asset   string `json:"asset"`
	}
	c.ShouldBindJSON(&body)
	prompt := fmt.Sprintf(`You are a security operations AI analyst. A SOAR approval request needs review.
Action: %s. Asset: %s. Context: %s.
Respond with JSON: { "risk_summary": string, "business_impact": string, "recommendation": "approve"|"reject"|"more_info", "reasons": [string], "confidence": 0-100, "mitre_context": string, "suggested_conditions": [string] }`,
		body.Action, body.Asset, body.Context)
	raw, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"risk_summary":         "This action will isolate a potentially compromised endpoint from the network, preventing lateral movement but disrupting the user's workflow.",
			"business_impact":      "Medium — user will lose network access for estimated 2-4 hours during investigation. No production services on this host.",
			"recommendation":       "approve",
			"reasons":              []interface{}{"Cobalt Strike C2 communication confirmed to known malicious IP", "LSASS credential dump detected — high risk of lateral movement if not isolated", "Host is a workstation, not production infrastructure — business impact is manageable", "Isolation is reversible and is standard procedure for confirmed IOCs"},
			"confidence":           94,
			"mitre_context":        "T1055.012 Process Hollowing, T1003.001 LSASS Memory, T1562.001 Defense Evasion — standard pre-ransomware pattern",
			"suggested_conditions": []interface{}{"Collect memory dump before isolation", "Notify user manager before executing", "Verify backup approver is available for 24h coverage"},
		})
		return
	}
	if idx := strings.Index(raw, "```json"); idx != -1 {
		raw = raw[idx+7:]
	} else if idx := strings.Index(raw, "```"); idx != -1 {
		raw = raw[idx+3:]
	}
	if idx := strings.LastIndex(raw, "```"); idx != -1 {
		raw = raw[:idx]
	}
	c.Data(http.StatusOK, "application/json", []byte(strings.TrimSpace(raw)))
}

// PostAQReport — POST /api/aq/report
func PostAQReport(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	var body struct {
		ReportType string `json:"report_type"`
		Period     string `json:"period"`
	}
	c.ShouldBindJSON(&body)
	if body.ReportType == "" {
		body.ReportType = "approval_history"
	}

	var total, approved, rejected, emergency int
	var avgTime, slaCompliance float64
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND status='approved'`, tid).Scan(&approved)
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND status='rejected'`, tid).Scan(&rejected)
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND is_emergency=true`, tid).Scan(&emergency)
	database.DB.QueryRow(`SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (approved_at-created_at))/60),0) FROM aq_requests WHERE tenant_id=$1 AND status='approved'`, tid).Scan(&avgTime)
	database.DB.QueryRow(`
		SELECT CASE WHEN COUNT(*) FILTER (WHERE status IN ('approved','rejected')) > 0
			THEN 100.0 * COUNT(*) FILTER (WHERE status='approved' AND approved_at <= due_at) / COUNT(*) FILTER (WHERE status IN ('approved','rejected'))
			ELSE 100.0 END
		FROM aq_requests WHERE tenant_id=$1`, tid).Scan(&slaCompliance)

	type requestorRow struct {
		Requestor    string `json:"requestor"`
		Count        int    `json:"count"`
		AutoApproved int    `json:"auto_approved"`
	}
	topRequestors := []requestorRow{}
	rRows, _ := database.DB.Query(`
		SELECT requester, COUNT(*), COUNT(*) FILTER (WHERE policy='automatic')
		FROM aq_requests WHERE tenant_id=$1 AND requester != '' GROUP BY requester ORDER BY COUNT(*) DESC LIMIT 5`, tid)
	if rRows != nil {
		defer rRows.Close()
		for rRows.Next() {
			var r requestorRow
			if rRows.Scan(&r.Requestor, &r.Count, &r.AutoApproved) == nil {
				topRequestors = append(topRequestors, r)
			}
		}
	}

	type riskRow struct {
		Level       string `json:"level"`
		Count       int    `json:"count"`
		AllApproved bool   `json:"all_approved"`
	}
	riskBreakdown := []riskRow{}
	kRows, _ := database.DB.Query(`
		SELECT risk_level, COUNT(*), COUNT(*) FILTER (WHERE status NOT IN ('approved','pending'))=0
		FROM aq_requests WHERE tenant_id=$1 GROUP BY risk_level ORDER BY COUNT(*) DESC`, tid)
	if kRows != nil {
		defer kRows.Close()
		for kRows.Next() {
			var r riskRow
			if kRows.Scan(&r.Level, &r.Count, &r.AllApproved) == nil {
				riskBreakdown = append(riskBreakdown, r)
			}
		}
	}

	prompt := fmt.Sprintf(`You are a SOAR approval-queue reporting assistant. Write a %s report based on these REAL metrics for this period: %d total requests, %d approved, %d rejected, %d emergency overrides, %.1f minutes average approval time, %.1f%% SLA compliance. Respond as a JSON object with fields: summary (2-3 sentences grounded only in these numbers, no invented incidents), recommendations (a JSON array of up to 3 short actionable strings based on the real data given — if there isn't enough data, say so instead of inventing findings).`,
		body.ReportType, total, approved, rejected, emergency, avgTime, slaCompliance)
	var summary string
	var recommendations []string
	raw, err := services.CallLLM(prompt)
	if err == nil {
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
			Summary         string   `json:"summary"`
			Recommendations []string `json:"recommendations"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(clean)), &parsed) == nil {
			summary = parsed.Summary
			recommendations = parsed.Recommendations
		}
	}
	if summary == "" {
		if total == 0 {
			summary = "No approval requests have been recorded for this tenant yet."
		} else {
			summary = fmt.Sprintf("%d approval requests processed this period, %d approved and %d rejected, with a %.1f%% SLA compliance rate.", total, approved, rejected, slaCompliance)
		}
		recommendations = []string{}
	}

	c.JSON(http.StatusOK, gin.H{
		"title":          fmt.Sprintf("Approval Queue %s Report — %s", strings.Title(strings.ReplaceAll(body.ReportType, "_", " ")), time.Now().Format("Jan 2006")),
		"generated_at":   time.Now().Format(time.RFC3339),
		"report_type":    body.ReportType,
		"classification": "CONFIDENTIAL — INTERNAL",
		"summary":        summary,
		"statistics": gin.H{
			"total":          total,
			"approved":       approved,
			"rejected":       rejected,
			"emergency":      emergency,
			"avg_time_min":   avgTime,
			"sla_compliance": slaCompliance,
		},
		"top_requestors":  topRequestors,
		"risk_breakdown":  riskBreakdown,
		"recommendations": recommendations,
	})
}
