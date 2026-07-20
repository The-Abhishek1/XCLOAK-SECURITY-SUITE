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

// ── table creation ──────────────────────────────────────────────────────────

func createFCETables() {
	db := database.DB
	queries := []string{
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
	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			panic("fce table: " + err.Error())
		}
	}
}

func InitFCETables() { createFCETables() }

// ── helpers ─────────────────────────────────────────────────────────────────

func fceAudit(tid int, action, objType, objID, objName, actor, details string) {
	database.DB.Exec(
		`INSERT INTO fce_audit (tenant_id,action,object_type,object_id,object_name,actor,details)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		tid, action, objType, objID, objName, actor, details,
	)
}

func fceNotify(tid int, eventType, title, message, severity, frameworkID, controlID string) {
	database.DB.Exec(
		`INSERT INTO fce_notifications (tenant_id,event_type,title,message,severity,framework_id,control_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		tid, eventType, title, message, severity, fceNullStr(frameworkID), fceNullStr(controlID),
	)
}

func fceNullStr(s string) interface{} {
	if s == "" { return nil }
	return s
}

func fceID(prefix string) string {
	return fmt.Sprintf("%s-%06d", prefix, rand.Intn(999999))
}

// ── dashboard ───────────────────────────────────────────────────────────────

func GetFCEDashboard(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB

	var totalFrameworks, activeFrameworks, passedControls, failedControls, notAssessed, openRemediations int
	var overallScore float64
	db.QueryRow(`SELECT COUNT(*) FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE`, tid).Scan(&activeFrameworks)
	db.QueryRow(`SELECT COUNT(*) FROM fce_frameworks WHERE tenant_id=$1`, tid).Scan(&totalFrameworks)
	db.QueryRow(`SELECT COALESCE(AVG(overall_score),0) FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE`, tid).Scan(&overallScore)
	db.QueryRow(`SELECT COALESCE(SUM(passed_controls),0) FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE`, tid).Scan(&passedControls)
	db.QueryRow(`SELECT COALESCE(SUM(failed_controls),0) FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE`, tid).Scan(&failedControls)
	db.QueryRow(`SELECT COALESCE(SUM(not_assessed),0) FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE`, tid).Scan(&notAssessed)
	db.QueryRow(`SELECT COUNT(*) FROM fce_remediations WHERE tenant_id=$1 AND status NOT IN ('closed','cancelled')`, tid).Scan(&openRemediations)

	var criticalFindings int
	db.QueryRow(`SELECT COUNT(*) FROM fce_controls WHERE tenant_id=$1 AND risk_level='critical' AND assessment_status='failed'`, tid).Scan(&criticalFindings)

	// compliance status breakdown
	type statusCount struct {
		Status string `json:"status"`
		Count  int    `json:"count"`
	}
	srows, _ := db.Query(`SELECT compliance_status, COUNT(*) FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE GROUP BY compliance_status`, tid)
	statusBreakdown := []statusCount{}
	if srows != nil {
		defer srows.Close()
		for srows.Next() {
			var r statusCount
			srows.Scan(&r.Status, &r.Count)
			statusBreakdown = append(statusBreakdown, r)
		}
	}

	// top failing frameworks
	type frameworkScore struct {
		FrameworkID string `json:"framework_id"`
		Name        string `json:"name"`
		Score       int    `json:"overall_score"`
		Failed      int    `json:"failed_controls"`
		Status      string `json:"compliance_status"`
	}
	frows, _ := db.Query(`SELECT framework_id, name, overall_score, failed_controls, compliance_status FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE ORDER BY overall_score ASC LIMIT 5`, tid)
	bottomFrameworks := []frameworkScore{}
	if frows != nil {
		defer frows.Close()
		for frows.Next() {
			var r frameworkScore
			frows.Scan(&r.FrameworkID, &r.Name, &r.Score, &r.Failed, &r.Status)
			bottomFrameworks = append(bottomFrameworks, r)
		}
	}

	// overdue remediations
	var overdueCount int
	db.QueryRow(`SELECT COUNT(*) FROM fce_remediations WHERE tenant_id=$1 AND status NOT IN ('closed','cancelled') AND due_date < NOW()`, tid).Scan(&overdueCount)

	// audit readiness score: weighted average with penalties
	auditReadiness := int(overallScore)
	if criticalFindings > 0 {
		auditReadiness -= criticalFindings * 5
	}
	if overdueCount > 0 {
		auditReadiness -= overdueCount * 3
	}
	if auditReadiness < 0 { auditReadiness = 0 }
	if auditReadiness > 100 { auditReadiness = 100 }

	c.JSON(http.StatusOK, gin.H{
		"total_frameworks":   totalFrameworks,
		"active_frameworks":  activeFrameworks,
		"overall_score":      int(overallScore),
		"passed_controls":    passedControls,
		"failed_controls":    failedControls,
		"not_assessed":       notAssessed,
		"critical_findings":  criticalFindings,
		"open_remediations":  openRemediations,
		"overdue_count":      overdueCount,
		"audit_readiness":    auditReadiness,
		"status_breakdown":   statusBreakdown,
		"bottom_frameworks":  bottomFrameworks,
	})
}

// ── frameworks ───────────────────────────────────────────────────────────────

func GetFCEFrameworks(c *gin.Context) {
	tid := tenantIDFromContext(c)
	category := c.Query("category")
	q := `SELECT id, framework_id, name, version, category, description, total_controls,
		  passed_controls, failed_controls, not_applicable, not_assessed, overall_score,
		  compliance_status, last_assessment_at, next_assessment_at, owner, is_active,
		  is_builtin, tags, created_at, updated_at
		  FROM fce_frameworks WHERE tenant_id=$1`
	args := []interface{}{tid}
	if category != "" {
		q += ` AND category=$2`
		args = append(args, category)
	}
	q += ` ORDER BY category, overall_score ASC`

	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type Row struct {
		ID               int        `json:"id"`
		FrameworkID      string     `json:"framework_id"`
		Name             string     `json:"name"`
		Version          string     `json:"version"`
		Category         string     `json:"category"`
		Description      *string    `json:"description"`
		TotalControls    int        `json:"total_controls"`
		PassedControls   int        `json:"passed_controls"`
		FailedControls   int        `json:"failed_controls"`
		NotApplicable    int        `json:"not_applicable"`
		NotAssessed      int        `json:"not_assessed"`
		OverallScore     int        `json:"overall_score"`
		ComplianceStatus string     `json:"compliance_status"`
		LastAssessment   *time.Time `json:"last_assessment_at"`
		NextAssessment   *time.Time `json:"next_assessment_at"`
		Owner            *string    `json:"owner"`
		IsActive         bool       `json:"is_active"`
		IsBuiltin        bool       `json:"is_builtin"`
		Tags             string     `json:"tags"`
		CreatedAt        time.Time  `json:"created_at"`
		UpdatedAt        time.Time  `json:"updated_at"`
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.FrameworkID, &r.Name, &r.Version, &r.Category, &r.Description,
			&r.TotalControls, &r.PassedControls, &r.FailedControls, &r.NotApplicable, &r.NotAssessed,
			&r.OverallScore, &r.ComplianceStatus, &r.LastAssessment, &r.NextAssessment,
			&r.Owner, &r.IsActive, &r.IsBuiltin, &r.Tags, &r.CreatedAt, &r.UpdatedAt)
		result = append(result, r)
	}
	c.JSON(http.StatusOK, result)
}

func PostFCEFramework(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var body struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		Category    string `json:"category"`
		Description string `json:"description"`
		Owner       string `json:"owner"`
		Tags        string `json:"tags"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	if body.Category == "" { body.Category = "custom" }
	if body.Version == "" { body.Version = "1.0" }
	if body.Tags == "" { body.Tags = "[]" }
	fid := fceID("FWK")
	var id int
	err := database.DB.QueryRow(
		`INSERT INTO fce_frameworks (tenant_id,framework_id,name,version,category,description,owner,tags)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		tid, fid, body.Name, body.Version, body.Category,
		fceNullStr(body.Description), fceNullStr(body.Owner), body.Tags,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	fceAudit(tid, "framework_added", "framework", fid, body.Name, actor, fmt.Sprintf("Category: %s, Version: %s", body.Category, body.Version))
	c.JSON(http.StatusOK, gin.H{"id": id, "framework_id": fid})
}

func PatchFCEFramework(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id := c.Param("id")
	var body map[string]interface{}
	c.ShouldBindJSON(&body)
	var name, fid string
	database.DB.QueryRow(`SELECT name, framework_id FROM fce_frameworks WHERE id=$1 AND tenant_id=$2`, id, tid).Scan(&name, &fid)
	sets := []string{"updated_at=NOW()"}
	args := []interface{}{}
	i := 1
	for _, k := range []string{"name", "version", "category", "description", "owner", "is_active", "overall_score", "compliance_status", "passed_controls", "failed_controls", "not_assessed"} {
		if v, ok := body[k]; ok {
			sets = append(sets, fmt.Sprintf("%s=$%d", k, i))
			args = append(args, v)
			i++
		}
	}
	args = append(args, id, tid)
	database.DB.Exec(fmt.Sprintf(`UPDATE fce_frameworks SET %s WHERE id=$%d AND tenant_id=$%d`, strings.Join(sets, ","), i, i+1), args...)
	fceAudit(tid, "framework_modified", "framework", fid, name, actor, "Framework definition updated")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func DeleteFCEFramework(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id := c.Param("id")
	var name, fid string
	database.DB.QueryRow(`SELECT name, framework_id FROM fce_frameworks WHERE id=$1 AND tenant_id=$2`, id, tid).Scan(&name, &fid)
	database.DB.Exec(`DELETE FROM fce_frameworks WHERE id=$1 AND tenant_id=$2`, id, tid)
	fceAudit(tid, "framework_deleted", "framework", fid, name, actor, "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── controls ─────────────────────────────────────────────────────────────────

func GetFCEControls(c *gin.Context) {
	tid := tenantIDFromContext(c)
	frameworkID := c.Query("framework_id")
	status := c.Query("status")
	risk := c.Query("risk_level")
	search := c.Query("search")
	limit := parseLimit(c, 500)

	q := `SELECT id, framework_id, control_id, name, description, category, priority,
		  requirement, assessment_status, risk_level, owner, evidence_count, notes,
		  last_reviewed_at, reviewed_by, score, created_at, updated_at
		  FROM fce_controls WHERE tenant_id=$1`
	args := []interface{}{tid}
	idx := 2
	if frameworkID != "" {
		q += fmt.Sprintf(` AND framework_id=$%d`, idx); args = append(args, frameworkID); idx++
	}
	if status != "" {
		q += fmt.Sprintf(` AND assessment_status=$%d`, idx); args = append(args, status); idx++
	}
	if risk != "" {
		q += fmt.Sprintf(` AND risk_level=$%d`, idx); args = append(args, risk); idx++
	}
	if search != "" {
		q += fmt.Sprintf(` AND (name ILIKE $%d OR control_id ILIKE $%d OR description ILIKE $%d)`, idx, idx, idx)
		args = append(args, "%"+search+"%"); idx++
	}
	q += fmt.Sprintf(` ORDER BY framework_id, control_id LIMIT $%d`, idx)
	args = append(args, limit)

	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type Row struct {
		ID               int        `json:"id"`
		FrameworkID      string     `json:"framework_id"`
		ControlID        string     `json:"control_id"`
		Name             string     `json:"name"`
		Description      *string    `json:"description"`
		Category         string     `json:"category"`
		Priority         string     `json:"priority"`
		Requirement      *string    `json:"requirement"`
		AssessmentStatus string     `json:"assessment_status"`
		RiskLevel        string     `json:"risk_level"`
		Owner            *string    `json:"owner"`
		EvidenceCount    int        `json:"evidence_count"`
		Notes            *string    `json:"notes"`
		LastReviewedAt   *time.Time `json:"last_reviewed_at"`
		ReviewedBy       *string    `json:"reviewed_by"`
		Score            int        `json:"score"`
		CreatedAt        time.Time  `json:"created_at"`
		UpdatedAt        time.Time  `json:"updated_at"`
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.FrameworkID, &r.ControlID, &r.Name, &r.Description, &r.Category,
			&r.Priority, &r.Requirement, &r.AssessmentStatus, &r.RiskLevel, &r.Owner,
			&r.EvidenceCount, &r.Notes, &r.LastReviewedAt, &r.ReviewedBy, &r.Score,
			&r.CreatedAt, &r.UpdatedAt)
		result = append(result, r)
	}
	c.JSON(http.StatusOK, result)
}

func PatchFCEControl(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id := c.Param("id")
	var body map[string]interface{}
	c.ShouldBindJSON(&body)
	var name, cid, fid string
	database.DB.QueryRow(`SELECT name, control_id, framework_id FROM fce_controls WHERE id=$1 AND tenant_id=$2`, id, tid).Scan(&name, &cid, &fid)
	sets := []string{"updated_at=NOW()"}
	args := []interface{}{}
	i := 1
	for _, k := range []string{"assessment_status", "risk_level", "owner", "notes", "score", "reviewed_by"} {
		if v, ok := body[k]; ok {
			sets = append(sets, fmt.Sprintf("%s=$%d", k, i))
			args = append(args, v)
			i++
		}
	}
	// mark last_reviewed_at
	sets = append(sets, fmt.Sprintf("last_reviewed_at=$%d, reviewed_by=$%d", i, i+1))
	args = append(args, time.Now(), actor)
	i += 2
	args = append(args, id, tid)
	database.DB.Exec(fmt.Sprintf(`UPDATE fce_controls SET %s WHERE id=$%d AND tenant_id=$%d`, strings.Join(sets, ","), i, i+1), args...)
	fceAudit(tid, "control_modified", "control", cid, name, actor, fmt.Sprintf("Framework: %s", fid))
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── evidence ─────────────────────────────────────────────────────────────────

func GetFCEEvidence(c *gin.Context) {
	tid := tenantIDFromContext(c)
	frameworkID := c.Query("framework_id")
	controlID := c.Query("control_id")
	q := `SELECT id, evidence_id, framework_id, control_id, name, description, evidence_type,
		  file_name, file_size_bytes, file_hash, source, uploaded_by, verified, verified_by,
		  verified_at, expires_at, tags, created_at
		  FROM fce_evidence WHERE tenant_id=$1`
	args := []interface{}{tid}
	idx := 2
	if frameworkID != "" {
		q += fmt.Sprintf(` AND framework_id=$%d`, idx); args = append(args, frameworkID); idx++
	}
	if controlID != "" {
		q += fmt.Sprintf(` AND control_id=$%d`, idx); args = append(args, controlID); idx++
	}
	q += ` ORDER BY created_at DESC LIMIT 200`
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type Row struct {
		ID           int        `json:"id"`
		EvidenceID   string     `json:"evidence_id"`
		FrameworkID  string     `json:"framework_id"`
		ControlID    *string    `json:"control_id"`
		Name         string     `json:"name"`
		Description  *string    `json:"description"`
		EvidenceType string     `json:"evidence_type"`
		FileName     *string    `json:"file_name"`
		FileSize     int64      `json:"file_size_bytes"`
		FileHash     *string    `json:"file_hash"`
		Source       *string    `json:"source"`
		UploadedBy   string     `json:"uploaded_by"`
		Verified     bool       `json:"verified"`
		VerifiedBy   *string    `json:"verified_by"`
		VerifiedAt   *time.Time `json:"verified_at"`
		ExpiresAt    *time.Time `json:"expires_at"`
		Tags         string     `json:"tags"`
		CreatedAt    time.Time  `json:"created_at"`
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.EvidenceID, &r.FrameworkID, &r.ControlID, &r.Name, &r.Description,
			&r.EvidenceType, &r.FileName, &r.FileSize, &r.FileHash, &r.Source, &r.UploadedBy,
			&r.Verified, &r.VerifiedBy, &r.VerifiedAt, &r.ExpiresAt, &r.Tags, &r.CreatedAt)
		result = append(result, r)
	}
	c.JSON(http.StatusOK, result)
}

func PostFCEEvidence(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var body struct {
		FrameworkID  string `json:"framework_id"`
		ControlID    string `json:"control_id"`
		Name         string `json:"name"`
		Description  string `json:"description"`
		EvidenceType string `json:"evidence_type"`
		FileName     string `json:"file_name"`
		Source       string `json:"source"`
		Tags         string `json:"tags"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	if body.EvidenceType == "" { body.EvidenceType = "document" }
	if body.Tags == "" { body.Tags = "[]" }
	eid := fceID("EVD")
	var id int
	database.DB.QueryRow(
		`INSERT INTO fce_evidence (tenant_id,evidence_id,framework_id,control_id,name,description,evidence_type,file_name,source,uploaded_by,tags)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id`,
		tid, eid, body.FrameworkID, fceNullStr(body.ControlID), body.Name,
		fceNullStr(body.Description), body.EvidenceType, fceNullStr(body.FileName),
		fceNullStr(body.Source), actor, body.Tags,
	).Scan(&id)
	// update control evidence count
	if body.ControlID != "" {
		database.DB.Exec(`UPDATE fce_controls SET evidence_count=evidence_count+1 WHERE control_id=$1 AND framework_id=$2 AND tenant_id=$3`,
			body.ControlID, body.FrameworkID, tid)
	}
	fceAudit(tid, "evidence_uploaded", "evidence", eid, body.Name, actor, fmt.Sprintf("Framework: %s, Control: %s, Type: %s", body.FrameworkID, body.ControlID, body.EvidenceType))
	c.JSON(http.StatusOK, gin.H{"id": id, "evidence_id": eid})
}

func DeleteFCEEvidence(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id := c.Param("id")
	var name, eid string
	database.DB.QueryRow(`SELECT name, evidence_id FROM fce_evidence WHERE id=$1 AND tenant_id=$2`, id, tid).Scan(&name, &eid)
	database.DB.Exec(`DELETE FROM fce_evidence WHERE id=$1 AND tenant_id=$2`, id, tid)
	fceAudit(tid, "evidence_deleted", "evidence", eid, name, actor, "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── gap analysis ──────────────────────────────────────────────────────────────

func GetFCEGapAnalysis(c *gin.Context) {
	tid := tenantIDFromContext(c)
	frameworkID := c.Query("framework_id")

	q := `SELECT framework_id, control_id, name, category, risk_level, assessment_status, score, evidence_count
		  FROM fce_controls WHERE tenant_id=$1 AND assessment_status IN ('failed','not_assessed')`
	args := []interface{}{tid}
	if frameworkID != "" {
		q += ` AND framework_id=$2`
		args = append(args, frameworkID)
	}
	q += ` ORDER BY CASE risk_level WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, framework_id`

	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type GapRow struct {
		FrameworkID string `json:"framework_id"`
		ControlID   string `json:"control_id"`
		Name        string `json:"name"`
		Category    string `json:"category"`
		RiskLevel   string `json:"risk_level"`
		Status      string `json:"status"`
		Score       int    `json:"score"`
		Evidence    int    `json:"evidence_count"`
	}
	gaps := []GapRow{}
	var criticalCount, highCount, missingEvidence int
	for rows.Next() {
		var r GapRow
		rows.Scan(&r.FrameworkID, &r.ControlID, &r.Name, &r.Category, &r.RiskLevel, &r.Status, &r.Score, &r.Evidence)
		if r.RiskLevel == "critical" { criticalCount++ }
		if r.RiskLevel == "high" { highCount++ }
		if r.Evidence == 0 { missingEvidence++ }
		gaps = append(gaps, r)
	}

	c.JSON(http.StatusOK, gin.H{
		"gaps":             gaps,
		"total_gaps":       len(gaps),
		"critical_count":   criticalCount,
		"high_count":       highCount,
		"missing_evidence": missingEvidence,
	})
}

// ── assessments ───────────────────────────────────────────────────────────────

func GetFCEAssessments(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(
		`SELECT id, assessment_id, framework_id, framework_name, assessment_type, status,
		 started_at, completed_at, started_by, total_controls, passed, failed, not_applicable, not_assessed, score, notes
		 FROM fce_assessments WHERE tenant_id=$1 ORDER BY started_at DESC LIMIT 100`, tid)
	if rows == nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()
	type Row struct {
		ID             int        `json:"id"`
		AssessmentID   string     `json:"assessment_id"`
		FrameworkID    string     `json:"framework_id"`
		FrameworkName  string     `json:"framework_name"`
		Type           string     `json:"assessment_type"`
		Status         string     `json:"status"`
		StartedAt      time.Time  `json:"started_at"`
		CompletedAt    *time.Time `json:"completed_at"`
		StartedBy      string     `json:"started_by"`
		TotalControls  int        `json:"total_controls"`
		Passed         int        `json:"passed"`
		Failed         int        `json:"failed"`
		NotApplicable  int        `json:"not_applicable"`
		NotAssessed    int        `json:"not_assessed"`
		Score          int        `json:"score"`
		Notes          *string    `json:"notes"`
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.AssessmentID, &r.FrameworkID, &r.FrameworkName, &r.Type, &r.Status,
			&r.StartedAt, &r.CompletedAt, &r.StartedBy, &r.TotalControls, &r.Passed, &r.Failed,
			&r.NotApplicable, &r.NotAssessed, &r.Score, &r.Notes)
		result = append(result, r)
	}
	c.JSON(http.StatusOK, result)
}

func PostFCEAssessment(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var body struct {
		FrameworkID   string `json:"framework_id"`
		FrameworkName string `json:"framework_name"`
		Type          string `json:"assessment_type"`
		Notes         string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.FrameworkID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "framework_id required"})
		return
	}
	if body.Type == "" { body.Type = "manual" }

	// count controls
	var total, passed, failed, na, notAssessed int
	database.DB.QueryRow(`SELECT COUNT(*) FROM fce_controls WHERE tenant_id=$1 AND framework_id=$2`, tid, body.FrameworkID).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM fce_controls WHERE tenant_id=$1 AND framework_id=$2 AND assessment_status='passed'`, tid, body.FrameworkID).Scan(&passed)
	database.DB.QueryRow(`SELECT COUNT(*) FROM fce_controls WHERE tenant_id=$1 AND framework_id=$2 AND assessment_status='failed'`, tid, body.FrameworkID).Scan(&failed)
	database.DB.QueryRow(`SELECT COUNT(*) FROM fce_controls WHERE tenant_id=$1 AND framework_id=$2 AND assessment_status='not_applicable'`, tid, body.FrameworkID).Scan(&na)
	database.DB.QueryRow(`SELECT COUNT(*) FROM fce_controls WHERE tenant_id=$1 AND framework_id=$2 AND assessment_status='not_assessed'`, tid, body.FrameworkID).Scan(&notAssessed)

	score := 0
	if total-na > 0 {
		score = passed * 100 / (total - na)
	}

	aid := fceID("ASS")
	now := time.Now()
	var id int
	database.DB.QueryRow(
		`INSERT INTO fce_assessments (tenant_id,assessment_id,framework_id,framework_name,assessment_type,status,started_by,started_at,completed_at,total_controls,passed,failed,not_applicable,not_assessed,score,notes)
		 VALUES ($1,$2,$3,$4,$5,'completed',$6,$7,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id`,
		tid, aid, body.FrameworkID, body.FrameworkName, body.Type, actor, now,
		total, passed, failed, na, notAssessed, score, fceNullStr(body.Notes),
	).Scan(&id)

	// update framework score
	database.DB.Exec(`UPDATE fce_frameworks SET overall_score=$1, passed_controls=$2, failed_controls=$3, not_assessed=$4, last_assessment_at=$5, updated_at=NOW() WHERE framework_id=$6 AND tenant_id=$7`,
		score, passed, failed, notAssessed, now, body.FrameworkID, tid)

	fceAudit(tid, "assessment_completed", "assessment", aid, body.FrameworkName, actor,
		fmt.Sprintf("Score: %d%%, Passed: %d, Failed: %d", score, passed, failed))
	fceNotify(tid, "assessment_completed", "Assessment Completed",
		fmt.Sprintf("%s assessment completed — score: %d%%", body.FrameworkName, score),
		"info", body.FrameworkID, "")
	c.JSON(http.StatusOK, gin.H{"id": id, "assessment_id": aid, "score": score})
}

// ── remediations ──────────────────────────────────────────────────────────────

func GetFCERemediations(c *gin.Context) {
	tid := tenantIDFromContext(c)
	status := c.Query("status")
	fwID := c.Query("framework_id")
	q := `SELECT id, remediation_id, framework_id, control_id, control_name, title, description,
		  priority, status, assigned_to, assigned_team, due_date, linked_vulns, linked_cases,
		  linked_playbooks, verification_status, verified_by, verified_at, closed_at, notes, created_by, created_at, updated_at
		  FROM fce_remediations WHERE tenant_id=$1`
	args := []interface{}{tid}
	idx := 2
	if status != "" {
		q += fmt.Sprintf(` AND status=$%d`, idx); args = append(args, status); idx++
	}
	if fwID != "" {
		q += fmt.Sprintf(` AND framework_id=$%d`, idx); args = append(args, fwID); idx++
	}
	q += ` ORDER BY CASE priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, due_date ASC NULLS LAST`

	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type Row struct {
		ID                 int        `json:"id"`
		RemediationID      string     `json:"remediation_id"`
		FrameworkID        string     `json:"framework_id"`
		ControlID          string     `json:"control_id"`
		ControlName        string     `json:"control_name"`
		Title              string     `json:"title"`
		Description        *string    `json:"description"`
		Priority           string     `json:"priority"`
		Status             string     `json:"status"`
		AssignedTo         *string    `json:"assigned_to"`
		AssignedTeam       *string    `json:"assigned_team"`
		DueDate            *string    `json:"due_date"`
		LinkedVulns        string     `json:"linked_vulns"`
		LinkedCases        string     `json:"linked_cases"`
		LinkedPlaybooks    string     `json:"linked_playbooks"`
		VerificationStatus string     `json:"verification_status"`
		VerifiedBy         *string    `json:"verified_by"`
		VerifiedAt         *time.Time `json:"verified_at"`
		ClosedAt           *time.Time `json:"closed_at"`
		Notes              *string    `json:"notes"`
		CreatedBy          string     `json:"created_by"`
		CreatedAt          time.Time  `json:"created_at"`
		UpdatedAt          time.Time  `json:"updated_at"`
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.RemediationID, &r.FrameworkID, &r.ControlID, &r.ControlName,
			&r.Title, &r.Description, &r.Priority, &r.Status, &r.AssignedTo, &r.AssignedTeam,
			&r.DueDate, &r.LinkedVulns, &r.LinkedCases, &r.LinkedPlaybooks,
			&r.VerificationStatus, &r.VerifiedBy, &r.VerifiedAt, &r.ClosedAt, &r.Notes,
			&r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
		result = append(result, r)
	}
	c.JSON(http.StatusOK, result)
}

func PostFCERemediation(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var body struct {
		FrameworkID  string `json:"framework_id"`
		ControlID    string `json:"control_id"`
		ControlName  string `json:"control_name"`
		Title        string `json:"title"`
		Description  string `json:"description"`
		Priority     string `json:"priority"`
		AssignedTo   string `json:"assigned_to"`
		AssignedTeam string `json:"assigned_team"`
		DueDate      string `json:"due_date"`
		Notes        string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Title == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "title required"})
		return
	}
	if body.Priority == "" { body.Priority = "medium" }
	rid := fceID("REM")
	var id int
	database.DB.QueryRow(
		`INSERT INTO fce_remediations (tenant_id,remediation_id,framework_id,control_id,control_name,title,description,priority,assigned_to,assigned_team,due_date,created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
		tid, rid, body.FrameworkID, body.ControlID, body.ControlName, body.Title,
		fceNullStr(body.Description), body.Priority, fceNullStr(body.AssignedTo),
		fceNullStr(body.AssignedTeam), fceNullStr(body.DueDate), actor,
	).Scan(&id)
	fceAudit(tid, "remediation_created", "remediation", rid, body.Title, actor, fmt.Sprintf("Control: %s, Priority: %s", body.ControlID, body.Priority))
	c.JSON(http.StatusOK, gin.H{"id": id, "remediation_id": rid})
}

func PatchFCERemediation(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id := c.Param("id")
	var body map[string]interface{}
	c.ShouldBindJSON(&body)
	var title, rid string
	database.DB.QueryRow(`SELECT title, remediation_id FROM fce_remediations WHERE id=$1 AND tenant_id=$2`, id, tid).Scan(&title, &rid)
	sets := []string{"updated_at=NOW()"}
	args := []interface{}{}
	i := 1
	for _, k := range []string{"status", "priority", "assigned_to", "assigned_team", "due_date", "notes", "verification_status", "verified_by"} {
		if v, ok := body[k]; ok {
			sets = append(sets, fmt.Sprintf("%s=$%d", k, i))
			args = append(args, v)
			i++
		}
	}
	if st, ok := body["status"]; ok && (st == "closed" || st == "verified") {
		sets = append(sets, fmt.Sprintf("closed_at=$%d", i))
		args = append(args, time.Now())
		i++
	}
	args = append(args, id, tid)
	database.DB.Exec(fmt.Sprintf(`UPDATE fce_remediations SET %s WHERE id=$%d AND tenant_id=$%d`, strings.Join(sets, ","), i, i+1), args...)
	fceAudit(tid, "remediation_updated", "remediation", rid, title, actor, "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── notifications ─────────────────────────────────────────────────────────────

func GetFCENotifications(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(
		`SELECT id, event_type, title, message, severity, framework_id, control_id, read, created_at
		 FROM fce_notifications WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100`, tid)
	if rows == nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()
	type Row struct {
		ID          int       `json:"id"`
		EventType   string    `json:"event_type"`
		Title       string    `json:"title"`
		Message     string    `json:"message"`
		Severity    string    `json:"severity"`
		FrameworkID *string   `json:"framework_id"`
		ControlID   *string   `json:"control_id"`
		Read        bool      `json:"read"`
		CreatedAt   time.Time `json:"created_at"`
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.EventType, &r.Title, &r.Message, &r.Severity, &r.FrameworkID, &r.ControlID, &r.Read, &r.CreatedAt)
		result = append(result, r)
	}
	c.JSON(http.StatusOK, result)
}

func PatchFCENotificationsRead(c *gin.Context) {
	tid := tenantIDFromContext(c)
	database.DB.Exec(`UPDATE fce_notifications SET read=TRUE WHERE tenant_id=$1`, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── analytics ─────────────────────────────────────────────────────────────────

func GetFCEAnalytics(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB

	type fwScore struct {
		Name   string `json:"name"`
		Score  int    `json:"score"`
		Status string `json:"status"`
	}
	frows, _ := db.Query(`SELECT name, overall_score, compliance_status FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE ORDER BY overall_score DESC`, tid)
	byFramework := []fwScore{}
	if frows != nil {
		defer frows.Close()
		for frows.Next() {
			var r fwScore
			frows.Scan(&r.Name, &r.Score, &r.Status)
			byFramework = append(byFramework, r)
		}
	}

	type catFail struct {
		Category string `json:"category"`
		Count    int    `json:"count"`
	}
	crows, _ := db.Query(`SELECT category, COUNT(*) FROM fce_controls WHERE tenant_id=$1 AND assessment_status='failed' GROUP BY category ORDER BY COUNT(*) DESC LIMIT 8`, tid)
	failedByCategory := []catFail{}
	if crows != nil {
		defer crows.Close()
		for crows.Next() {
			var r catFail
			crows.Scan(&r.Category, &r.Count)
			failedByCategory = append(failedByCategory, r)
		}
	}

	type riskDist struct {
		Risk  string `json:"risk_level"`
		Count int    `json:"count"`
	}
	rrows, _ := db.Query(`SELECT risk_level, COUNT(*) FROM fce_controls WHERE tenant_id=$1 AND assessment_status='failed' GROUP BY risk_level ORDER BY COUNT(*) DESC`, tid)
	riskDistribution := []riskDist{}
	if rrows != nil {
		defer rrows.Close()
		for rrows.Next() {
			var r riskDist
			rrows.Scan(&r.Risk, &r.Count)
			riskDistribution = append(riskDistribution, r)
		}
	}

	var totalRemediations, closedRemediations, overdueRemediations int
	db.QueryRow(`SELECT COUNT(*) FROM fce_remediations WHERE tenant_id=$1`, tid).Scan(&totalRemediations)
	db.QueryRow(`SELECT COUNT(*) FROM fce_remediations WHERE tenant_id=$1 AND status='closed'`, tid).Scan(&closedRemediations)
	db.QueryRow(`SELECT COUNT(*) FROM fce_remediations WHERE tenant_id=$1 AND status NOT IN ('closed','cancelled') AND due_date < NOW()`, tid).Scan(&overdueRemediations)
	var totalEvidence, verifiedEvidence int
	db.QueryRow(`SELECT COUNT(*) FROM fce_evidence WHERE tenant_id=$1`, tid).Scan(&totalEvidence)
	db.QueryRow(`SELECT COUNT(*) FROM fce_evidence WHERE tenant_id=$1 AND verified=TRUE`, tid).Scan(&verifiedEvidence)

	remediationProgress := 0
	if totalRemediations > 0 {
		remediationProgress = closedRemediations * 100 / totalRemediations
	}

	c.JSON(http.StatusOK, gin.H{
		"by_framework":          byFramework,
		"failed_by_category":    failedByCategory,
		"risk_distribution":     riskDistribution,
		"total_remediations":    totalRemediations,
		"closed_remediations":   closedRemediations,
		"overdue_remediations":  overdueRemediations,
		"remediation_progress":  remediationProgress,
		"total_evidence":        totalEvidence,
		"verified_evidence":     verifiedEvidence,
	})
}

// ── audit ─────────────────────────────────────────────────────────────────────

func GetFCEAudit(c *gin.Context) {
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)
	rows, _ := database.DB.Query(
		`SELECT id, action, object_type, object_id, object_name, actor, details, created_at
		 FROM fce_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tid, limit)
	if rows == nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()
	type Row struct {
		ID         int       `json:"id"`
		Action     string    `json:"action"`
		ObjectType string    `json:"object_type"`
		ObjectID   *string   `json:"object_id"`
		ObjectName *string   `json:"object_name"`
		Actor      string    `json:"actor"`
		Details    *string   `json:"details"`
		CreatedAt  time.Time `json:"created_at"`
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.Action, &r.ObjectType, &r.ObjectID, &r.ObjectName, &r.Actor, &r.Details, &r.CreatedAt)
		result = append(result, r)
	}
	c.JSON(http.StatusOK, result)
}

// ── AI ─────────────────────────────────────────────────────────────────────────

func PostFCEAI(c *gin.Context) {
	tid := tenantIDFromContext(c)
	var body struct {
		Action    string `json:"action"`
		Framework string `json:"framework"`
		Context   string `json:"context"`
	}
	c.ShouldBindJSON(&body)

	db := database.DB

	// ── Gather real compliance context for this tenant ──────────────────────
	var ctx strings.Builder
	frows, _ := db.Query(`SELECT name, overall_score, failed_controls, passed_controls, compliance_status
		FROM fce_frameworks WHERE tenant_id=$1 AND is_active=TRUE ORDER BY overall_score ASC`, tid)
	if frows != nil {
		ctx.WriteString("Active frameworks:\n")
		for frows.Next() {
			var name, status string
			var score, failed, passed int
			frows.Scan(&name, &score, &failed, &passed, &status)
			fmt.Fprintf(&ctx, "- %s: %d%% (%s), %d failed / %d passed controls\n", name, score, status, failed, passed)
		}
		frows.Close()
	}

	crows, _ := db.Query(`SELECT c.control_id, c.name, f.name, c.risk_level, c.category
		FROM fce_controls c JOIN fce_frameworks f ON f.id=c.framework_id
		WHERE c.tenant_id=$1 AND c.assessment_status='failed'
		ORDER BY CASE c.risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END LIMIT 10`, tid)
	if crows != nil {
		ctx.WriteString("\nTop failing controls:\n")
		for crows.Next() {
			var cid, cname, fname, risk, cat string
			crows.Scan(&cid, &cname, &fname, &risk, &cat)
			fmt.Fprintf(&ctx, "- [%s] %s %s (%s) — risk:%s category:%s\n", fname, cid, cname, "failed", risk, cat)
		}
		crows.Close()
	}

	rrows, _ := db.Query(`SELECT title, status, due_date FROM fce_remediations
		WHERE tenant_id=$1 AND status NOT IN ('closed','cancelled') ORDER BY due_date ASC NULLS LAST LIMIT 10`, tid)
	if rrows != nil {
		ctx.WriteString("\nOpen remediations:\n")
		for rrows.Next() {
			var title, status string
			var due *time.Time
			rrows.Scan(&title, &status, &due)
			dueStr := "no due date"
			if due != nil {
				dueStr = due.Format("2006-01-02")
			}
			fmt.Fprintf(&ctx, "- %s (%s, due %s)\n", title, status, dueStr)
		}
		rrows.Close()
	}

	var overdueCount int
	db.QueryRow(`SELECT COUNT(*) FROM fce_remediations WHERE tenant_id=$1 AND status NOT IN ('closed','cancelled') AND due_date < NOW()`, tid).Scan(&overdueCount)
	fmt.Fprintf(&ctx, "\nOverdue remediations: %d\n", overdueCount)

	if body.Framework != "" {
		fmt.Fprintf(&ctx, "\nFocus framework: %s\n", body.Framework)
	}
	if body.Context != "" {
		fmt.Fprintf(&ctx, "\nAdditional context: %s\n", body.Context)
	}
	compliancectx := ctx.String()

	var task string
	switch body.Action {
	case "compliance_summary":
		task = "Write a concise compliance posture summary across all active frameworks, framework by framework, ending with an overall weighted assessment and top priority."
	case "explain_failures":
		task = "Analyze the top failing controls and explain, for each, what the gap likely means and its potential impact if exploited or found in an audit."
	case "recommend_remediation":
		task = "Produce a prioritized remediation roadmap (immediate/short-term/long-term) for the failing controls and open remediations, with rough effort estimates."
	case "suggest_evidence":
		task = "List the audit evidence that should be gathered for the active frameworks, grouped by framework."
	case "predict_audit_readiness":
		task = "Assess current audit readiness given the framework scores and open remediations, call out critical gaps that would cause audit failure, and project readiness once open items are resolved."
	case "executive_summary":
		task = "Write a compliance executive briefing for leadership: overall posture, key risks, and a recommended decision, in a business (not technical) tone."
	default:
		c.JSON(400, gin.H{"error": "unknown action"})
		return
	}

	prompt := fmt.Sprintf(`You are a compliance analyst reviewing this organization's real framework compliance data.

%s

Task: %s

Base your answer strictly on the data above. If data is sparse, say so rather than inventing specifics. Respond in plain text (no markdown headers), suitable for direct display to the user.`, compliancectx, task)

	resp, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"response": strings.TrimSpace(resp), "action": body.Action})
}
