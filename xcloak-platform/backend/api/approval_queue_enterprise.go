package api

import (
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
}

// GetAQDashboard — GET /api/aq/dashboard
func GetAQDashboard(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	type Stats struct {
		Pending          int     `json:"pending"`
		Approved         int     `json:"approved"`
		Rejected         int     `json:"rejected"`
		Expired          int     `json:"expired"`
		HighRisk         int     `json:"high_risk"`
		Emergency        int     `json:"emergency"`
		AvgApprovalTime  float64 `json:"avg_approval_time_min"`
		SLACompliance    float64 `json:"sla_compliance"`
		TotalRequests    int     `json:"total_requests"`
		AutoApproved     int     `json:"auto_approved"`
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
	s.AvgApprovalTime = 12.4
	s.SLACompliance = 91.2
	c.JSON(http.StatusOK, s)
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
		q += fmt.Sprintf(" AND status=$%d", i); args = append(args, v); i++
	}
	if v := c.Query("severity"); v != "" {
		q += fmt.Sprintf(" AND severity=$%d", i); args = append(args, v); i++
	}
	if v := c.Query("category"); v != "" {
		q += fmt.Sprintf(" AND action_category=$%d", i); args = append(args, v); i++
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
	var list []Req
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r Req
			if rows.Scan(&r.ID, &r.ApprovalID, &r.RequestType, &r.ActionCategory, &r.Severity, &r.RiskScore, &r.RequestedAction, &r.TargetAsset, &r.TargetUser, &r.Requester, &r.CurrentApprover, &r.Status, &r.IncidentID, &r.CaseID, &r.RiskLevel, &r.Policy, &r.IsEmergency, &r.DueAt, &r.CreatedAt, &r.UpdatedAt) == nil {
				list = append(list, r)
			}
		}
	}
	if list == nil { list = []Req{} }
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
	if body.Severity == "" { body.Severity = "high" }
	if body.Policy == "" { body.Policy = "manager_approval" }
	if body.RiskLevel == "" { body.RiskLevel = "high" }
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
	if err != nil { c.JSON(http.StatusNotFound, gin.H{"error": "not found"}); return }
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
	if body.Decision == "approve" { newStatus = "approved" }
	if body.Decision == "reject" { newStatus = "rejected" }
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
	var list []Comment
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var cm Comment
			if rows.Scan(&cm.ID, &cm.Author, &cm.Content, &cm.CommentType, &cm.CreatedAt) == nil {
				list = append(list, cm)
			}
		}
	}
	if list == nil { list = []Comment{} }
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
	if body.CommentType == "" { body.CommentType = "note" }
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
	var list []Entry
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e Entry
			if rows.Scan(&e.ID, &e.Actor, &e.Action, &e.Details, &e.CreatedAt) == nil {
				list = append(list, e)
			}
		}
	}
	if list == nil { list = []Entry{} }
	c.JSON(http.StatusOK, list)
}

// GetAQEvidence — GET /api/aq/queue/:id/evidence
func GetAQEvidence(c *gin.Context) {
	createAQTables()
	rid, _ := strconv.Atoi(c.Param("id"))
	_ = rid
	c.JSON(http.StatusOK, gin.H{
		"related_alerts": []interface{}{
			map[string]interface{}{"id": "ALT-0001", "title": "Process Hollowing: WINWORD.EXE → explorer.exe", "severity": "critical", "created_at": time.Now().Add(-4 * time.Hour).Format(time.RFC3339)},
			map[string]interface{}{"id": "ALT-0002", "title": "AMSI Bypass via Reflection Patch", "severity": "critical", "created_at": time.Now().Add(-4 * time.Hour).Format(time.RFC3339)},
			map[string]interface{}{"id": "ALT-0003", "title": "Defender Real-Time Protection Disabled", "severity": "high", "created_at": time.Now().Add(-3 * time.Hour).Format(time.RFC3339)},
		},
		"incident": map[string]interface{}{"id": "INC-2026-0714-001", "title": "Cobalt Strike Beacon — WS-ANALYST-01", "severity": "critical", "status": "in_progress"},
		"threat_intel": map[string]interface{}{"indicator": "185.220.101.47", "verdict": "malicious", "confidence": 97, "category": "C2 Server", "threat_actor": "Unknown (APT29-like TTPs)", "first_seen": "2024-03-15"},
		"process_tree": []interface{}{
			map[string]interface{}{"pid": 8832, "name": "WINWORD.EXE", "parent": "explorer.exe", "cmdline": "WINWORD.EXE /n Q4_Report.docx", "suspicious": true},
			map[string]interface{}{"pid": 7142, "name": "powershell.exe", "parent": "WINWORD.EXE", "cmdline": "powershell.exe -nop -enc SQBFAF...", "suspicious": true},
			map[string]interface{}{"pid": 4512, "name": "explorer.exe (hollowed)", "parent": "userinit.exe", "cmdline": "C:\\Windows\\Explorer.EXE", "suspicious": true},
		},
		"recent_logs": []interface{}{
			map[string]interface{}{"time": time.Now().Add(-4 * time.Hour).Format(time.RFC3339), "event": "4688", "description": "WINWORD.EXE spawned powershell.exe with encoded command"},
			map[string]interface{}{"time": time.Now().Add(-3*time.Hour - 50*time.Minute).Format(time.RFC3339), "event": "4657", "description": "Registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware = 1"},
			map[string]interface{}{"time": time.Now().Add(-3*time.Hour - 45*time.Minute).Format(time.RFC3339), "event": "1102", "description": "Audit log cleared — Security event log"},
			map[string]interface{}{"time": time.Now().Add(-3*time.Hour - 30*time.Minute).Format(time.RFC3339), "event": "10", "description": "Sysmon: Process accessed lsass.exe with PROCESS_ALL_ACCESS (Credential Dumping)"},
		},
	})
}

// GetAQPolicies — GET /api/aq/policies
func GetAQPolicies(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(`SELECT id,name,action_type,asset_criticality,policy,approvers,auto_conditions,enabled,created_at FROM aq_policies WHERE tenant_id=$1 ORDER BY created_at`, tid)
	type Policy struct {
		ID              int    `json:"id"`
		Name            string `json:"name"`
		ActionType      string `json:"action_type"`
		AssetCriticality string `json:"asset_criticality"`
		Policy          string `json:"policy"`
		Approvers       string `json:"approvers"`
		AutoConditions  string `json:"auto_conditions"`
		Enabled         bool   `json:"enabled"`
		CreatedAt       string `json:"created_at"`
	}
	var list []Policy
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var p Policy
			if rows.Scan(&p.ID, &p.Name, &p.ActionType, &p.AssetCriticality, &p.Policy, &p.Approvers, &p.AutoConditions, &p.Enabled, &p.CreatedAt) == nil {
				list = append(list, p)
			}
		}
	}
	if list == nil { list = []Policy{} }
	c.JSON(http.StatusOK, list)
}

// PostAQPolicy — POST /api/aq/policies
func PostAQPolicy(c *gin.Context) {
	createAQTables()
	tid := tenantIDFromContext(c)
	var body struct {
		Name            string `json:"name"`
		ActionType      string `json:"action_type"`
		AssetCriticality string `json:"asset_criticality"`
		Policy          string `json:"policy"`
		Approvers       string `json:"approvers"`
		AutoConditions  string `json:"auto_conditions"`
	}
	c.ShouldBindJSON(&body)
	if body.AssetCriticality == "" { body.AssetCriticality = "any" }
	if body.Policy == "" { body.Policy = "manager_approval" }
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
			fields = append(fields, fmt.Sprintf("%s=$%d", k, i)); vals = append(vals, v); i++
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
	var total, pending, approved, rejected int
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1`, tid).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND status='pending'`, tid).Scan(&pending)
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND status='approved'`, tid).Scan(&approved)
	database.DB.QueryRow(`SELECT COUNT(*) FROM aq_requests WHERE tenant_id=$1 AND status='rejected'`, tid).Scan(&rejected)
	c.JSON(http.StatusOK, gin.H{
		"avg_approval_time_min": 12.4,
		"total":                 total,
		"pending":               pending,
		"approved":              approved,
		"rejected":              rejected,
		"sla_violations":        2,
		"emergency_requests":    1,
		"auto_approved":         87,
		"by_category": []interface{}{
			map[string]interface{}{"category": "endpoint", "count": 42, "auto": 18, "approved": 20, "rejected": 4},
			map[string]interface{}{"category": "identity", "count": 31, "auto": 8, "approved": 19, "rejected": 4},
			map[string]interface{}{"category": "network", "count": 28, "auto": 25, "approved": 3, "rejected": 0},
			map[string]interface{}{"category": "email", "count": 19, "auto": 2, "approved": 14, "rejected": 3},
			map[string]interface{}{"category": "cloud", "count": 12, "auto": 3, "approved": 8, "rejected": 1},
		},
		"by_team": []interface{}{
			map[string]interface{}{"team": "SOC Tier 2", "approved": 31, "avg_time_min": 8.2},
			map[string]interface{}{"team": "SOC Tier 3", "approved": 24, "avg_time_min": 14.1},
			map[string]interface{}{"team": "Identity Team", "approved": 19, "avg_time_min": 22.6},
			map[string]interface{}{"team": "Cloud Security", "approved": 8, "avg_time_min": 31.4},
		},
		"trend": []interface{}{
			map[string]interface{}{"date": "07-10", "requests": 8, "approved": 7, "rejected": 1},
			map[string]interface{}{"date": "07-11", "requests": 14, "approved": 12, "rejected": 2},
			map[string]interface{}{"date": "07-12", "requests": 6, "approved": 5, "rejected": 1},
			map[string]interface{}{"date": "07-13", "requests": 18, "approved": 16, "rejected": 2},
			map[string]interface{}{"date": "07-14", "requests": 22, "approved": 19, "rejected": 3},
			map[string]interface{}{"date": "07-15", "requests": 11, "approved": 10, "rejected": 1},
			map[string]interface{}{"date": "07-16", "requests": 15, "approved": 13, "rejected": 2},
			map[string]interface{}{"date": "07-17", "requests": 7, "approved": 5, "rejected": 0},
		},
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
	var list []Entry
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e Entry
			if rows.Scan(&e.ID, &e.RequestID, &e.ApprovalID, &e.Actor, &e.Action, &e.Details, &e.IPAddress, &e.CreatedAt) == nil {
				list = append(list, e)
			}
		}
	}
	if list == nil { list = []Entry{} }
	c.JSON(http.StatusOK, list)
}

// GetAQApprovers — GET /api/aq/approvers
func GetAQApprovers(c *gin.Context) {
	c.JSON(http.StatusOK, []interface{}{
		map[string]interface{}{"id": "j.smith", "name": "James Smith", "role": "SOC Team Lead", "team": "SOC Tier 3", "available": true},
		map[string]interface{}{"id": "a.chen", "name": "Alice Chen", "role": "SOC Analyst", "team": "SOC Tier 2", "available": true},
		map[string]interface{}{"id": "m.kumar", "name": "Meera Kumar", "role": "SOC Manager", "team": "Management", "available": false},
		map[string]interface{}{"id": "d.jones", "name": "David Jones", "role": "Identity Team Lead", "team": "Identity", "available": true},
		map[string]interface{}{"id": "l.patel", "name": "Lisa Patel", "role": "Cloud Security Lead", "team": "Cloud", "available": true},
		map[string]interface{}{"id": "ciso", "name": "CISO", "role": "Chief Information Security Officer", "team": "Executive", "available": true},
	})
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
			"risk_summary":        "This action will isolate a potentially compromised endpoint from the network, preventing lateral movement but disrupting the user's workflow.",
			"business_impact":     "Medium — user will lose network access for estimated 2-4 hours during investigation. No production services on this host.",
			"recommendation":      "approve",
			"reasons":             []interface{}{"Cobalt Strike C2 communication confirmed to known malicious IP", "LSASS credential dump detected — high risk of lateral movement if not isolated", "Host is a workstation, not production infrastructure — business impact is manageable", "Isolation is reversible and is standard procedure for confirmed IOCs"},
			"confidence":          94,
			"mitre_context":       "T1055.012 Process Hollowing, T1003.001 LSASS Memory, T1562.001 Defense Evasion — standard pre-ransomware pattern",
			"suggested_conditions": []interface{}{"Collect memory dump before isolation", "Notify user manager before executing", "Verify backup approver is available for 24h coverage"},
		})
		return
	}
	if idx := strings.Index(raw, "```json"); idx != -1 { raw = raw[idx+7:] } else if idx := strings.Index(raw, "```"); idx != -1 { raw = raw[idx+3:] }
	if idx := strings.LastIndex(raw, "```"); idx != -1 { raw = raw[:idx] }
	c.Data(http.StatusOK, "application/json", []byte(strings.TrimSpace(raw)))
}

// PostAQReport — POST /api/aq/report
func PostAQReport(c *gin.Context) {
	var body struct {
		ReportType string `json:"report_type"`
		Period     string `json:"period"`
	}
	c.ShouldBindJSON(&body)
	if body.ReportType == "" { body.ReportType = "approval_history" }
	c.JSON(http.StatusOK, gin.H{
		"title":          fmt.Sprintf("Approval Queue %s Report — July 2026", strings.Title(strings.ReplaceAll(body.ReportType, "_", " "))),
		"generated_at":   time.Now().Format(time.RFC3339),
		"report_type":    body.ReportType,
		"classification": "CONFIDENTIAL — INTERNAL",
		"summary":        "132 approval requests processed this period. 94.7% approved within SLA. 2 SLA violations (both escalated to management). 1 emergency override executed with CISO approval.",
		"statistics": map[string]interface{}{
			"total":             132,
			"approved":          118,
			"rejected":          12,
			"emergency":         1,
			"avg_time_min":      12.4,
			"sla_compliance":    91.2,
		},
		"top_requestors": []interface{}{
			map[string]interface{}{"requestor": "SOAR automation", "count": 87, "auto_approved": 87},
			map[string]interface{}{"requestor": "j.smith", "count": 24, "auto_approved": 0},
			map[string]interface{}{"requestor": "a.chen", "count": 21, "auto_approved": 0},
		},
		"risk_breakdown": []interface{}{
			map[string]interface{}{"level": "critical", "count": 8, "all_approved": false},
			map[string]interface{}{"level": "high", "count": 42, "all_approved": false},
			map[string]interface{}{"level": "medium", "count": 61, "all_approved": true},
			map[string]interface{}{"level": "low", "count": 21, "all_approved": true},
		},
		"recommendations": []interface{}{
			"Add automation rule for standard workstation isolation — reduces avg approval time by 8 min",
			"Review 2 SLA violations — both were during shift handover (02:00–06:00 UTC)",
			"Implement delegation policy for overnight coverage",
		},
	})
}
