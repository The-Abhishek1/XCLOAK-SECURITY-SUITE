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

func createRPETables() {
	db := database.DB
	queries := []string{
		`CREATE TABLE IF NOT EXISTS rpe_reports (
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
			generation_count INTEGER DEFAULT 0,
			schedule_id TEXT,
			created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW(),
			UNIQUE(tenant_id, report_id)
		)`,
		`CREATE TABLE IF NOT EXISTS rpe_templates (
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
		)`,
		`CREATE TABLE IF NOT EXISTS rpe_schedules (
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
		)`,
		`CREATE TABLE IF NOT EXISTS rpe_executions (
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
			error_message TEXT,
			download_url TEXT,
			created_at TIMESTAMP DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS rpe_exports (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			export_id TEXT NOT NULL,
			report_id TEXT NOT NULL, report_name TEXT NOT NULL,
			execution_id TEXT,
			format TEXT NOT NULL DEFAULT 'pdf',
			file_size_bytes BIGINT DEFAULT 0,
			exported_by TEXT NOT NULL,
			download_url TEXT,
			expires_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS rpe_versions (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			report_id TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
			author TEXT NOT NULL, changes TEXT,
			snapshot TEXT DEFAULT '{}',
			generated_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS rpe_shared (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			share_id TEXT NOT NULL UNIQUE,
			report_id TEXT NOT NULL, report_name TEXT NOT NULL,
			execution_id TEXT,
			shared_by TEXT NOT NULL,
			share_type TEXT NOT NULL DEFAULT 'internal',
			password_hash TEXT,
			allowed_roles TEXT DEFAULT '[]',
			view_count INTEGER DEFAULT 0,
			expires_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS rpe_notifications (
			id SERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,
			event_type TEXT NOT NULL,
			title TEXT NOT NULL, message TEXT NOT NULL,
			report_id TEXT, report_name TEXT,
			severity TEXT NOT NULL DEFAULT 'info',
			read BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS rpe_audit (
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
			panic("rpe table: " + err.Error())
		}
	}
}

func InitRPETables() { createRPETables() }

// ── helpers ─────────────────────────────────────────────────────────────────

func rpeAudit(tid int, action, objType, objID, objName, actor, details string) {
	database.DB.Exec(
		`INSERT INTO rpe_audit (tenant_id,action,object_type,object_id,object_name,actor,details)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		tid, action, objType, objID, objName, actor, details,
	)
}

func rpeNotify(tid int, eventType, title, message, severity, reportID, reportName string) {
	database.DB.Exec(
		`INSERT INTO rpe_notifications (tenant_id,event_type,title,message,severity,report_id,report_name)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		tid, eventType, title, message, severity, reportID, reportName,
	)
}

func rpeID(prefix string) string {
	return fmt.Sprintf("%s-%06d", prefix, rand.Intn(999999))
}

// ── dashboard ───────────────────────────────────────────────────────────────

func rpeNullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func GetRPEDashboard(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB

	var totalReports, scheduledReports, generatedToday, failedReports, reportTemplates, sharedReports, exportHistory int
	var storageBytes int64
	db.QueryRow(`SELECT COUNT(*) FROM rpe_reports WHERE tenant_id=$1 AND status='active'`, tid).Scan(&totalReports)
	db.QueryRow(`SELECT COUNT(*) FROM rpe_schedules WHERE tenant_id=$1 AND status='active'`, tid).Scan(&scheduledReports)
	db.QueryRow(`SELECT COUNT(*) FROM rpe_executions WHERE tenant_id=$1 AND started_at > NOW()-INTERVAL '24h' AND status='completed'`, tid).Scan(&generatedToday)
	db.QueryRow(`SELECT COUNT(*) FROM rpe_executions WHERE tenant_id=$1 AND started_at > NOW()-INTERVAL '24h' AND status='failed'`, tid).Scan(&failedReports)
	db.QueryRow(`SELECT COUNT(*) FROM rpe_templates WHERE tenant_id=$1`, tid).Scan(&reportTemplates)
	db.QueryRow(`SELECT COUNT(*) FROM rpe_shared WHERE tenant_id=$1 AND (expires_at IS NULL OR expires_at > NOW())`, tid).Scan(&sharedReports)
	db.QueryRow(`SELECT COUNT(*) FROM rpe_exports WHERE tenant_id=$1`, tid).Scan(&exportHistory)
	db.QueryRow(`SELECT COALESCE(SUM(file_size_bytes),0) FROM rpe_exports WHERE tenant_id=$1`, tid).Scan(&storageBytes)

	dash := map[string]interface{}{
		"total_reports":      totalReports,
		"scheduled_reports":  scheduledReports,
		"generated_today":    generatedToday,
		"failed_reports":     failedReports,
		"report_templates":   reportTemplates,
		"shared_reports":     sharedReports,
		"export_history":     exportHistory,
		"storage_bytes":      storageBytes,
	}

	// recent executions
	type execRow struct {
		ExecutionID string    `json:"execution_id"`
		ReportName  string    `json:"report_name"`
		Status      string    `json:"status"`
		Duration    *int      `json:"duration_ms"`
		ExecBy      string    `json:"executed_by"`
		StartedAt   time.Time `json:"started_at"`
	}
	rows, _ := db.Query(`SELECT execution_id, report_name, status, duration_ms, executed_by, started_at
		FROM rpe_executions WHERE tenant_id=$1 ORDER BY started_at DESC LIMIT 8`, tid)
	recentExecs := []execRow{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r execRow
			rows.Scan(&r.ExecutionID, &r.ReportName, &r.Status, &r.Duration, &r.ExecBy, &r.StartedAt)
			recentExecs = append(recentExecs, r)
		}
	}
	dash["recent_executions"] = recentExecs

	// category breakdown
	type catCount struct {
		Category string `json:"category"`
		Count    int    `json:"count"`
	}
	crows, _ := db.Query(`SELECT category, COUNT(*) FROM rpe_reports WHERE tenant_id=$1 AND status='active' GROUP BY category ORDER BY COUNT(*) DESC`, tid)
	cats := []catCount{}
	if crows != nil {
		defer crows.Close()
		for crows.Next() {
			var cc catCount
			crows.Scan(&cc.Category, &cc.Count)
			cats = append(cats, cc)
		}
	}
	dash["by_category"] = cats

	// schedule next-runs
	type schedRow struct {
		ScheduleID string     `json:"schedule_id"`
		ReportName string     `json:"report_name"`
		Frequency  string     `json:"frequency"`
		NextRun    *time.Time `json:"next_run_at"`
	}
	srows, _ := db.Query(`SELECT schedule_id, report_name, frequency, next_run_at
		FROM rpe_schedules WHERE tenant_id=$1 AND status='active' ORDER BY next_run_at ASC LIMIT 5`, tid)
	upcoming := []schedRow{}
	if srows != nil {
		defer srows.Close()
		for srows.Next() {
			var sr schedRow
			srows.Scan(&sr.ScheduleID, &sr.ReportName, &sr.Frequency, &sr.NextRun)
			upcoming = append(upcoming, sr)
		}
	}
	dash["upcoming_schedules"] = upcoming

	c.JSON(http.StatusOK, dash)
}

// ── report library ───────────────────────────────────────────────────────────

func GetRPEReports(c *gin.Context) {
	tid := tenantIDFromContext(c)
	search := c.Query("search")
	category := c.Query("category")
	status := c.Query("status")

	q := `SELECT id, report_id, name, description, category, report_type, template_id,
		data_sources, filters, sections, owner, status, tags,
		last_generated_at, last_generated_by, generation_count, schedule_id, created_at, updated_at
		FROM rpe_reports WHERE tenant_id=$1`
	args := []interface{}{tid}
	idx := 2
	if search != "" {
		q += fmt.Sprintf(` AND (name ILIKE $%d OR report_id ILIKE $%d OR description ILIKE $%d)`, idx, idx, idx)
		args = append(args, "%"+search+"%")
		idx++
	}
	if category != "" {
		q += fmt.Sprintf(` AND category=$%d`, idx)
		args = append(args, category)
		idx++
	}
	if status != "" {
		q += fmt.Sprintf(` AND status=$%d`, idx)
		args = append(args, status)
		idx++
	}
	q += ` ORDER BY updated_at DESC LIMIT 200`

	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type Row struct {
		ID              int        `json:"id"`
		ReportID        string     `json:"report_id"`
		Name            string     `json:"name"`
		Description     *string    `json:"description"`
		Category        string     `json:"category"`
		ReportType      string     `json:"report_type"`
		TemplateID      *string    `json:"template_id"`
		DataSources     string     `json:"data_sources"`
		Filters         string     `json:"filters"`
		Sections        string     `json:"sections"`
		Owner           string     `json:"owner"`
		Status          string     `json:"status"`
		Tags            string     `json:"tags"`
		LastGeneratedAt *time.Time `json:"last_generated_at"`
		LastGeneratedBy *string    `json:"last_generated_by"`
		GenerationCount int        `json:"generation_count"`
		ScheduleID      *string    `json:"schedule_id"`
		CreatedAt       time.Time  `json:"created_at"`
		UpdatedAt       time.Time  `json:"updated_at"`
	}
	results := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.ReportID, &r.Name, &r.Description, &r.Category, &r.ReportType, &r.TemplateID,
			&r.DataSources, &r.Filters, &r.Sections, &r.Owner, &r.Status, &r.Tags,
			&r.LastGeneratedAt, &r.LastGeneratedBy, &r.GenerationCount, &r.ScheduleID,
			&r.CreatedAt, &r.UpdatedAt)
		results = append(results, r)
	}
	c.JSON(http.StatusOK, results)
}

func PostRPEReport(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)

	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Category    string `json:"category"`
		ReportType  string `json:"report_type"`
		TemplateID  string `json:"template_id"`
		DataSources string `json:"data_sources"`
		Filters     string `json:"filters"`
		Sections    string `json:"sections"`
		Owner       string `json:"owner"`
		Tags        string `json:"tags"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	if body.Category == "" { body.Category = "security" }
	if body.ReportType == "" { body.ReportType = "custom" }
	if body.DataSources == "" { body.DataSources = "[]" }
	if body.Filters == "" { body.Filters = "{}" }
	if body.Sections == "" { body.Sections = "[]" }
	if body.Tags == "" { body.Tags = "[]" }
	if body.Owner == "" { body.Owner = actor }

	rid := rpeID("RPT")
	var id int
	err := database.DB.QueryRow(
		`INSERT INTO rpe_reports (tenant_id, report_id, name, description, category, report_type, template_id, data_sources, filters, sections, owner, tags)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
		tid, rid, body.Name, body.Description, body.Category, body.ReportType,
		rpeNullStr(body.TemplateID), body.DataSources, body.Filters, body.Sections, body.Owner, body.Tags,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	rpeAudit(tid, "report_created", "report", rid, body.Name, actor, fmt.Sprintf("Category: %s, Type: %s", body.Category, body.ReportType))
	c.JSON(http.StatusOK, gin.H{"id": id, "report_id": rid})
}

func PatchRPEReport(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id := c.Param("id")

	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var name, rid string
	database.DB.QueryRow(`SELECT name, report_id FROM rpe_reports WHERE id=$1 AND tenant_id=$2`, id, tid).Scan(&name, &rid)

	sets := []string{"updated_at=NOW()"}
	args := []interface{}{}
	i := 1
	for _, k := range []string{"name", "description", "status", "owner", "tags", "data_sources", "filters", "sections", "category", "report_type"} {
		if v, ok := body[k]; ok {
			sets = append(sets, fmt.Sprintf("%s=$%d", k, i))
			args = append(args, v)
			i++
		}
	}
	args = append(args, id, tid)
	database.DB.Exec(fmt.Sprintf(`UPDATE rpe_reports SET %s WHERE id=$%d AND tenant_id=$%d`, strings.Join(sets, ","), i, i+1), args...)
	rpeAudit(tid, "report_modified", "report", rid, name, actor, "Report definition updated")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func DeleteRPEReport(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id := c.Param("id")

	var name, rid string
	database.DB.QueryRow(`SELECT name, report_id FROM rpe_reports WHERE id=$1 AND tenant_id=$2`, id, tid).Scan(&name, &rid)
	database.DB.Exec(`DELETE FROM rpe_reports WHERE id=$1 AND tenant_id=$2`, id, tid)
	rpeAudit(tid, "report_deleted", "report", rid, name, actor, "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── templates ────────────────────────────────────────────────────────────────

func GetRPETemplates(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(
		`SELECT id, template_id, name, description, category, is_builtin, sections, default_data_sources, owner, use_count, created_at
		 FROM rpe_templates WHERE tenant_id=$1 ORDER BY is_builtin DESC, use_count DESC`, tid)
	if rows == nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()
	type Row struct {
		ID             int       `json:"id"`
		TemplateID     string    `json:"template_id"`
		Name           string    `json:"name"`
		Description    *string   `json:"description"`
		Category       string    `json:"category"`
		IsBuiltin      bool      `json:"is_builtin"`
		Sections       string    `json:"sections"`
		DataSources    string    `json:"default_data_sources"`
		Owner          *string   `json:"owner"`
		UseCount       int       `json:"use_count"`
		CreatedAt      time.Time `json:"created_at"`
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.TemplateID, &r.Name, &r.Description, &r.Category, &r.IsBuiltin, &r.Sections, &r.DataSources, &r.Owner, &r.UseCount, &r.CreatedAt)
		result = append(result, r)
	}
	c.JSON(http.StatusOK, result)
}

func PostRPETemplate(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)

	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Category    string `json:"category"`
		Sections    string `json:"sections"`
		DataSources string `json:"default_data_sources"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	if body.Category == "" { body.Category = "security" }
	if body.Sections == "" { body.Sections = "[]" }
	if body.DataSources == "" { body.DataSources = "[]" }
	tid2 := rpeID("TPL")
	var id int
	database.DB.QueryRow(
		`INSERT INTO rpe_templates (tenant_id, template_id, name, description, category, sections, default_data_sources, owner)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		tid, tid2, body.Name, body.Description, body.Category, body.Sections, body.DataSources, actor,
	).Scan(&id)
	rpeAudit(tid, "template_created", "template", tid2, body.Name, actor, "")
	c.JSON(http.StatusOK, gin.H{"id": id, "template_id": tid2})
}

func DeleteRPETemplate(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id := c.Param("id")
	var name, tmplID string
	database.DB.QueryRow(`SELECT name, template_id FROM rpe_templates WHERE id=$1 AND tenant_id=$2`, id, tid).Scan(&name, &tmplID)
	database.DB.Exec(`DELETE FROM rpe_templates WHERE id=$1 AND tenant_id=$2`, id, tid)
	rpeAudit(tid, "template_deleted", "template", tmplID, name, actor, "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── schedules ────────────────────────────────────────────────────────────────

func GetRPESchedules(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(
		`SELECT id, schedule_id, report_id, report_name, frequency, cron_expr, delivery_method,
		 recipients, webhook_url, export_format, status, last_run_at, next_run_at, run_count,
		 success_count, failure_count, created_by, created_at
		 FROM rpe_schedules WHERE tenant_id=$1 ORDER BY next_run_at ASC`, tid)
	if rows == nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()
	type Row struct {
		ID             int        `json:"id"`
		ScheduleID     string     `json:"schedule_id"`
		ReportID       string     `json:"report_id"`
		ReportName     string     `json:"report_name"`
		Frequency      string     `json:"frequency"`
		CronExpr       *string    `json:"cron_expr"`
		DeliveryMethod string     `json:"delivery_method"`
		Recipients     string     `json:"recipients"`
		WebhookURL     *string    `json:"webhook_url"`
		ExportFormat   string     `json:"export_format"`
		Status         string     `json:"status"`
		LastRunAt      *time.Time `json:"last_run_at"`
		NextRunAt      *time.Time `json:"next_run_at"`
		RunCount       int        `json:"run_count"`
		SuccessCount   int        `json:"success_count"`
		FailureCount   int        `json:"failure_count"`
		CreatedBy      string     `json:"created_by"`
		CreatedAt      time.Time  `json:"created_at"`
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.ScheduleID, &r.ReportID, &r.ReportName, &r.Frequency, &r.CronExpr,
			&r.DeliveryMethod, &r.Recipients, &r.WebhookURL, &r.ExportFormat, &r.Status,
			&r.LastRunAt, &r.NextRunAt, &r.RunCount, &r.SuccessCount, &r.FailureCount,
			&r.CreatedBy, &r.CreatedAt)
		result = append(result, r)
	}
	c.JSON(http.StatusOK, result)
}

func PostRPESchedule(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)

	var body struct {
		ReportID       string `json:"report_id"`
		ReportName     string `json:"report_name"`
		Frequency      string `json:"frequency"`
		CronExpr       string `json:"cron_expr"`
		DeliveryMethod string `json:"delivery_method"`
		Recipients     string `json:"recipients"`
		WebhookURL     string `json:"webhook_url"`
		ExportFormat   string `json:"export_format"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.ReportID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "report_id required"})
		return
	}
	if body.Frequency == "" { body.Frequency = "weekly" }
	if body.DeliveryMethod == "" { body.DeliveryMethod = "email" }
	if body.ExportFormat == "" { body.ExportFormat = "pdf" }
	if body.Recipients == "" { body.Recipients = "[]" }

	// compute next_run
	nextRun := time.Now().Add(24 * time.Hour)

	sid := rpeID("SCH")
	var id int
	database.DB.QueryRow(
		`INSERT INTO rpe_schedules (tenant_id, schedule_id, report_id, report_name, frequency, cron_expr, delivery_method, recipients, webhook_url, export_format, next_run_at, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
		tid, sid, body.ReportID, body.ReportName, body.Frequency, rpeNullStr(body.CronExpr),
		body.DeliveryMethod, body.Recipients, rpeNullStr(body.WebhookURL), body.ExportFormat, nextRun, actor,
	).Scan(&id)
	rpeAudit(tid, "report_scheduled", "schedule", sid, body.ReportName, actor, fmt.Sprintf("Frequency: %s, Delivery: %s", body.Frequency, body.DeliveryMethod))
	rpeNotify(tid, "report_scheduled", "Report Scheduled", fmt.Sprintf("'%s' scheduled (%s)", body.ReportName, body.Frequency), "info", body.ReportID, body.ReportName)
	c.JSON(http.StatusOK, gin.H{"id": id, "schedule_id": sid})
}

func PatchRPESchedule(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id := c.Param("id")

	var body map[string]interface{}
	c.ShouldBindJSON(&body)
	var name, sid string
	database.DB.QueryRow(`SELECT report_name, schedule_id FROM rpe_schedules WHERE id=$1 AND tenant_id=$2`, id, tid).Scan(&name, &sid)

	sets := []string{"updated_at=NOW()"}
	args := []interface{}{}
	i := 1
	for _, k := range []string{"frequency", "cron_expr", "delivery_method", "recipients", "status", "export_format"} {
		if v, ok := body[k]; ok {
			sets = append(sets, fmt.Sprintf("%s=$%d", k, i))
			args = append(args, v)
			i++
		}
	}
	args = append(args, id, tid)
	database.DB.Exec(fmt.Sprintf(`UPDATE rpe_schedules SET %s WHERE id=$%d AND tenant_id=$%d`, strings.Join(sets, ","), i, i+1), args...)
	rpeAudit(tid, "schedule_modified", "schedule", sid, name, actor, "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func DeleteRPESchedule(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id := c.Param("id")
	var name, sid string
	database.DB.QueryRow(`SELECT report_name, schedule_id FROM rpe_schedules WHERE id=$1 AND tenant_id=$2`, id, tid).Scan(&name, &sid)
	database.DB.Exec(`DELETE FROM rpe_schedules WHERE id=$1 AND tenant_id=$2`, id, tid)
	rpeAudit(tid, "schedule_deleted", "schedule", sid, name, actor, "")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── generate ─────────────────────────────────────────────────────────────────

func PostRPEGenerate(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	reportID := c.Param("id")

	var body struct {
		Format string `json:"format"`
	}
	c.ShouldBindJSON(&body)
	if body.Format == "" { body.Format = "pdf" }

	var reportName string
	database.DB.QueryRow(`SELECT name FROM rpe_reports WHERE report_id=$1 AND tenant_id=$2`, reportID, tid).Scan(&reportName)
	if reportName == "" {
		reportName = "Report " + reportID
	}

	// Simulate execution
	execID := rpeID("EXC")
	durMs := 800 + rand.Intn(3200)
	fileSize := int64(50000 + rand.Intn(500000))

	database.DB.Exec(
		`INSERT INTO rpe_executions (tenant_id, execution_id, report_id, report_name, started_at, completed_at, duration_ms, status, export_format, triggered_by, executed_by, file_size_bytes, download_url)
		 VALUES ($1,$2,$3,$4,NOW(),NOW(),$5,'completed',$6,'manual',$7,$8,$9)`,
		tid, execID, reportID, reportName, durMs, body.Format, actor, fileSize,
		fmt.Sprintf("/api/rpe/download/%s", execID),
	)
	database.DB.Exec(
		`UPDATE rpe_reports SET last_generated_at=NOW(), last_generated_by=$1, generation_count=generation_count+1, updated_at=NOW() WHERE report_id=$2 AND tenant_id=$3`,
		actor, reportID, tid,
	)
	// Export record
	expID := rpeID("EXP")
	database.DB.Exec(
		`INSERT INTO rpe_exports (tenant_id, export_id, report_id, report_name, execution_id, format, file_size_bytes, exported_by, download_url)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		tid, expID, reportID, reportName, execID, body.Format, fileSize, actor,
		fmt.Sprintf("/api/rpe/download/%s", execID),
	)
	rpeAudit(tid, "report_generated", "report", reportID, reportName, actor, fmt.Sprintf("Format: %s, Size: %d bytes", body.Format, fileSize))
	rpeNotify(tid, "report_generated", "Report Generated", fmt.Sprintf("'%s' generated successfully (%s)", reportName, body.Format), "info", reportID, reportName)

	c.JSON(http.StatusOK, gin.H{
		"execution_id": execID,
		"status":       "completed",
		"duration_ms":  durMs,
		"file_size":    fileSize,
		"download_url": fmt.Sprintf("/api/rpe/download/%s", execID),
	})
}

// ── executions ───────────────────────────────────────────────────────────────

func GetRPEExecutions(c *gin.Context) {
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)
	rows, _ := database.DB.Query(
		`SELECT id, execution_id, report_id, report_name, schedule_id, started_at, completed_at, duration_ms, status, export_format, triggered_by, executed_by, file_size_bytes, error_message, download_url
		 FROM rpe_executions WHERE tenant_id=$1 ORDER BY started_at DESC LIMIT $2`, tid, limit)
	if rows == nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()
	type Row struct {
		ID           int        `json:"id"`
		ExecutionID  string     `json:"execution_id"`
		ReportID     string     `json:"report_id"`
		ReportName   string     `json:"report_name"`
		ScheduleID   *string    `json:"schedule_id"`
		StartedAt    time.Time  `json:"started_at"`
		CompletedAt  *time.Time `json:"completed_at"`
		DurationMs   *int       `json:"duration_ms"`
		Status       string     `json:"status"`
		Format       string     `json:"export_format"`
		TriggeredBy  string     `json:"triggered_by"`
		ExecutedBy   string     `json:"executed_by"`
		FileSizeBytes int64     `json:"file_size_bytes"`
		ErrorMessage *string    `json:"error_message"`
		DownloadURL  *string    `json:"download_url"`
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.ExecutionID, &r.ReportID, &r.ReportName, &r.ScheduleID,
			&r.StartedAt, &r.CompletedAt, &r.DurationMs, &r.Status, &r.Format,
			&r.TriggeredBy, &r.ExecutedBy, &r.FileSizeBytes, &r.ErrorMessage, &r.DownloadURL)
		result = append(result, r)
	}
	c.JSON(http.StatusOK, result)
}

// ── exports ──────────────────────────────────────────────────────────────────

func GetRPEExports(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(
		`SELECT id, export_id, report_id, report_name, execution_id, format, file_size_bytes, exported_by, download_url, created_at
		 FROM rpe_exports WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100`, tid)
	if rows == nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()
	type Row struct {
		ID          int       `json:"id"`
		ExportID    string    `json:"export_id"`
		ReportID    string    `json:"report_id"`
		ReportName  string    `json:"report_name"`
		ExecutionID *string   `json:"execution_id"`
		Format      string    `json:"format"`
		FileSize    int64     `json:"file_size_bytes"`
		ExportedBy  string    `json:"exported_by"`
		DownloadURL *string   `json:"download_url"`
		CreatedAt   time.Time `json:"created_at"`
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.ExportID, &r.ReportID, &r.ReportName, &r.ExecutionID,
			&r.Format, &r.FileSize, &r.ExportedBy, &r.DownloadURL, &r.CreatedAt)
		result = append(result, r)
	}
	c.JSON(http.StatusOK, result)
}

// ── versions ─────────────────────────────────────────────────────────────────

func GetRPEVersions(c *gin.Context) {
	tid := tenantIDFromContext(c)
	reportID := c.Param("id")
	rows, _ := database.DB.Query(
		`SELECT id, version, author, changes, generated_at, created_at
		 FROM rpe_versions WHERE tenant_id=$1 AND report_id=$2 ORDER BY version DESC`, tid, reportID)
	if rows == nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()
	type Row struct {
		ID          int        `json:"id"`
		Version     int        `json:"version"`
		Author      string     `json:"author"`
		Changes     *string    `json:"changes"`
		GeneratedAt *time.Time `json:"generated_at"`
		CreatedAt   time.Time  `json:"created_at"`
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.Version, &r.Author, &r.Changes, &r.GeneratedAt, &r.CreatedAt)
		result = append(result, r)
	}
	c.JSON(http.StatusOK, result)
}

// ── sharing ──────────────────────────────────────────────────────────────────

func GetRPEShared(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(
		`SELECT id, share_id, report_id, report_name, shared_by, share_type, view_count, expires_at, created_at
		 FROM rpe_shared WHERE tenant_id=$1 ORDER BY created_at DESC`, tid)
	if rows == nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()
	type Row struct {
		ID         int        `json:"id"`
		ShareID    string     `json:"share_id"`
		ReportID   string     `json:"report_id"`
		ReportName string     `json:"report_name"`
		SharedBy   string     `json:"shared_by"`
		ShareType  string     `json:"share_type"`
		ViewCount  int        `json:"view_count"`
		ExpiresAt  *time.Time `json:"expires_at"`
		CreatedAt  time.Time  `json:"created_at"`
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.ShareID, &r.ReportID, &r.ReportName, &r.SharedBy, &r.ShareType, &r.ViewCount, &r.ExpiresAt, &r.CreatedAt)
		result = append(result, r)
	}
	c.JSON(http.StatusOK, result)
}

func PostRPEShare(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	reportID := c.Param("id")

	var body struct {
		ReportName   string `json:"report_name"`
		ShareType    string `json:"share_type"`
		ExpiresHours int    `json:"expires_hours"`
		Password     string `json:"password"`
	}
	c.ShouldBindJSON(&body)
	if body.ShareType == "" { body.ShareType = "internal" }

	var expAt *time.Time
	if body.ExpiresHours > 0 {
		t := time.Now().Add(time.Duration(body.ExpiresHours) * time.Hour)
		expAt = &t
	}
	shareID := rpeID("SHR")
	var id int
	database.DB.QueryRow(
		`INSERT INTO rpe_shared (tenant_id, share_id, report_id, report_name, shared_by, share_type, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		tid, shareID, reportID, body.ReportName, actor, body.ShareType, expAt,
	).Scan(&id)
	rpeAudit(tid, "report_shared", "report", reportID, body.ReportName, actor, fmt.Sprintf("Share type: %s", body.ShareType))
	rpeNotify(tid, "report_shared", "Report Shared", fmt.Sprintf("'%s' shared (%s) by %s", body.ReportName, body.ShareType, actor), "info", reportID, body.ReportName)
	c.JSON(http.StatusOK, gin.H{"id": id, "share_id": shareID, "share_url": fmt.Sprintf("/reports/shared/%s", shareID)})
}

// ── notifications ────────────────────────────────────────────────────────────

func GetRPENotifications(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, _ := database.DB.Query(
		`SELECT id, event_type, title, message, severity, report_id, report_name, read, created_at
		 FROM rpe_notifications WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100`, tid)
	if rows == nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()
	type Row struct {
		ID         int       `json:"id"`
		EventType  string    `json:"event_type"`
		Title      string    `json:"title"`
		Message    string    `json:"message"`
		Severity   string    `json:"severity"`
		ReportID   *string   `json:"report_id"`
		ReportName *string   `json:"report_name"`
		Read       bool      `json:"read"`
		CreatedAt  time.Time `json:"created_at"`
	}
	result := []Row{}
	for rows.Next() {
		var r Row
		rows.Scan(&r.ID, &r.EventType, &r.Title, &r.Message, &r.Severity, &r.ReportID, &r.ReportName, &r.Read, &r.CreatedAt)
		result = append(result, r)
	}
	c.JSON(http.StatusOK, result)
}

func PatchRPENotificationsRead(c *gin.Context) {
	tid := tenantIDFromContext(c)
	database.DB.Exec(`UPDATE rpe_notifications SET read=TRUE WHERE tenant_id=$1`, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── analytics ────────────────────────────────────────────────────────────────

func GetRPEAnalytics(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB

	type mostGen struct {
		ReportName string `json:"report_name"`
		Count      int    `json:"count"`
	}
	rows, _ := db.Query(
		`SELECT report_name, COUNT(*) as cnt FROM rpe_executions WHERE tenant_id=$1 GROUP BY report_name ORDER BY cnt DESC LIMIT 8`, tid)
	mostGenerated := []mostGen{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r mostGen
			rows.Scan(&r.ReportName, &r.Count)
			mostGenerated = append(mostGenerated, r)
		}
	}

	type formatStat struct {
		Format string `json:"format"`
		Count  int    `json:"count"`
	}
	frows, _ := db.Query(
		`SELECT format, COUNT(*) FROM rpe_exports WHERE tenant_id=$1 GROUP BY format ORDER BY COUNT(*) DESC`, tid)
	byFormat := []formatStat{}
	if frows != nil {
		defer frows.Close()
		for frows.Next() {
			var r formatStat
			frows.Scan(&r.Format, &r.Count)
			byFormat = append(byFormat, r)
		}
	}

	var totalExecs, successExecs, failedExecs int
	var avgDurationMs float64
	var storageBytes int64
	db.QueryRow(`SELECT COUNT(*), SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END), SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END), COALESCE(AVG(duration_ms),0) FROM rpe_executions WHERE tenant_id=$1`, tid).
		Scan(&totalExecs, &successExecs, &failedExecs, &avgDurationMs)
	db.QueryRow(`SELECT COALESCE(SUM(file_size_bytes),0) FROM rpe_exports WHERE tenant_id=$1`, tid).Scan(&storageBytes)

	successRate := 0.0
	if totalExecs > 0 {
		successRate = float64(successExecs) / float64(totalExecs) * 100
	}

	c.JSON(http.StatusOK, gin.H{
		"total_executions":       totalExecs,
		"success_executions":     successExecs,
		"failed_executions":      failedExecs,
		"success_rate":           fmt.Sprintf("%.1f", successRate),
		"avg_duration_ms":        int(avgDurationMs),
		"storage_bytes":          storageBytes,
		"most_generated":         mostGenerated,
		"by_export_format":       byFormat,
	})
}

// ── audit ────────────────────────────────────────────────────────────────────

func GetRPEAudit(c *gin.Context) {
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)
	rows, _ := database.DB.Query(
		`SELECT id, action, object_type, object_id, object_name, actor, details, created_at
		 FROM rpe_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tid, limit)
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

// ── AI ───────────────────────────────────────────────────────────────────────

func PostRPEAI(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB
	var body struct {
		Action  string `json:"action"`
		Context string `json:"context"`
	}
	c.ShouldBindJSON(&body)

	// ── Gather real cross-cutting security data for this tenant ─────────────
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

	frows, _ := db.Query(`SELECT name, overall_score, compliance_status FROM fce_frameworks
		WHERE tenant_id=$1 AND is_active=TRUE ORDER BY overall_score ASC LIMIT 6`, tid)
	if frows != nil {
		ctx.WriteString("Compliance frameworks:\n")
		for frows.Next() {
			var name, status string
			var score int
			frows.Scan(&name, &score, &status)
			fmt.Fprintf(&ctx, "- %s: %d%% (%s)\n", name, score, status)
		}
		frows.Close()
	}

	arows, _ := db.Query(`SELECT rule_name, severity, COUNT(*) FROM alerts WHERE tenant_id=$1
		AND created_at>=NOW()-INTERVAL '7 days' GROUP BY rule_name, severity ORDER BY COUNT(*) DESC LIMIT 8`, tid)
	if arows != nil {
		ctx.WriteString("Top alert rules (last 7 days):\n")
		for arows.Next() {
			var rule, sev string
			var cnt int
			arows.Scan(&rule, &sev, &cnt)
			fmt.Fprintf(&ctx, "- %s (%s): %d occurrences\n", rule, sev, cnt)
		}
		arows.Close()
	}

	if body.Context != "" {
		fmt.Fprintf(&ctx, "\nAdditional context: %s\n", body.Context)
	}
	reportctx := ctx.String()

	var task string
	switch body.Action {
	case "generate_report":
		task = "Recommend what security report to generate right now, based on what the data shows is most notable, and what sections it should cover."
	case "summarize_findings":
		task = "Write a concise security posture summary covering alerts, incidents, vulnerabilities, and compliance."
	case "highlight_risks":
		task = "List the risks requiring executive attention, ranked by severity, based on the data."
	case "explain_trends":
		task = "Explain what the alert/incident/vulnerability data suggests about trends and notable patterns. If there isn't enough data for a trend, say so."
	case "recommend_actions":
		task = "Write prioritized recommended actions based on the current data."
	case "executive_summary":
		task = "Write an executive security briefing: overall posture, key metrics, top business risks, and recommended board actions."
	default:
		c.JSON(400, gin.H{"error": "unknown action"})
		return
	}

	prompt := fmt.Sprintf(`You are a SOC reporting analyst reviewing this organization's real security data.

%s

Task: %s

Base your answer strictly on the data above — do not invent specific CVE numbers, IP addresses, or asset names not present in the data. If a metric is zero, treat that as a genuinely quiet period rather than fabricating an issue. Respond in plain text (no markdown headers), suitable for direct display to the user.`, reportctx, task)

	resp, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"response": strings.TrimSpace(resp), "action": body.Action})
}
