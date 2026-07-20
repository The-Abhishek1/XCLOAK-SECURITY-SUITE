package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/services"
)

func InitSRTables() { createSRTables() }

func createSRTables() {
	database.DB.Exec(`
	CREATE TABLE IF NOT EXISTS sr_scripts (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		tenant_id       INTEGER NOT NULL,
		script_id       TEXT NOT NULL,
		name            TEXT NOT NULL,
		description     TEXT,
		category        TEXT NOT NULL DEFAULT 'general',
		language        TEXT NOT NULL DEFAULT 'bash',
		version         TEXT NOT NULL DEFAULT '1.0.0',
		author          TEXT NOT NULL,
		status          TEXT NOT NULL DEFAULT 'active',
		content         TEXT NOT NULL DEFAULT '',
		tags            TEXT NOT NULL DEFAULT '[]',
		parameters      TEXT NOT NULL DEFAULT '[]',
		requires_approval INTEGER NOT NULL DEFAULT 0,
		is_signed       INTEGER NOT NULL DEFAULT 0,
		last_modified   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS sr_executions (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		tenant_id       INTEGER NOT NULL,
		execution_id    TEXT NOT NULL,
		script_id       TEXT NOT NULL,
		script_name     TEXT NOT NULL,
		target          TEXT NOT NULL,
		target_count    INTEGER NOT NULL DEFAULT 1,
		status          TEXT NOT NULL DEFAULT 'running',
		exit_code       INTEGER,
		stdout          TEXT,
		stderr          TEXT,
		execution_time  INTEGER,
		trigger_source  TEXT NOT NULL DEFAULT 'manual',
		run_as          TEXT NOT NULL DEFAULT 'system',
		parameters      TEXT NOT NULL DEFAULT '{}',
		executed_by     TEXT NOT NULL,
		approval_id     INTEGER,
		started_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		completed_at    DATETIME
	);
	CREATE TABLE IF NOT EXISTS sr_schedules (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		tenant_id       INTEGER NOT NULL,
		name            TEXT NOT NULL,
		script_id       TEXT NOT NULL,
		script_name     TEXT NOT NULL,
		schedule_type   TEXT NOT NULL DEFAULT 'once',
		cron_expr       TEXT,
		target          TEXT NOT NULL,
		run_as          TEXT NOT NULL DEFAULT 'system',
		parameters      TEXT NOT NULL DEFAULT '{}',
		enabled         INTEGER NOT NULL DEFAULT 1,
		last_run        DATETIME,
		next_run        DATETIME,
		created_by      TEXT NOT NULL,
		created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS sr_approvals (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		tenant_id       INTEGER NOT NULL,
		execution_id    TEXT NOT NULL,
		script_id       TEXT NOT NULL,
		script_name     TEXT NOT NULL,
		target          TEXT NOT NULL,
		run_as          TEXT NOT NULL,
		requested_by    TEXT NOT NULL,
		reason          TEXT,
		decision        TEXT NOT NULL DEFAULT 'pending',
		decided_by      TEXT,
		decided_at      DATETIME,
		created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS sr_audit (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		tenant_id       INTEGER NOT NULL,
		action          TEXT NOT NULL,
		script_id       TEXT,
		script_name     TEXT NOT NULL,
		actor           TEXT NOT NULL,
		details         TEXT,
		created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
}

func srAudit(tid int, scriptID, scriptName, action, actor, details string) {
	database.DB.Exec(
		`INSERT INTO sr_audit (tenant_id,action,script_id,script_name,actor,details) VALUES (?,?,?,?,?,?)`,
		tid, action, scriptID, scriptName, actor, details,
	)
}

// ── Dashboard ──────────────────────────────────────────────────────────────

func GetSRDashboard(c *gin.Context) {
	tid := tenantIDFromContext(c)
	row := func(q string) int {
		var n int
		database.DB.QueryRow(q, tid).Scan(&n)
		return n
	}
	avgTime := 0
	database.DB.QueryRow(`SELECT COALESCE(AVG(execution_time),0) FROM sr_executions WHERE tenant_id=? AND execution_time IS NOT NULL`, tid).Scan(&avgTime)

	c.JSON(http.StatusOK, gin.H{
		"total_scripts":        row(`SELECT COUNT(*) FROM sr_scripts WHERE tenant_id=?`),
		"active_scripts":       row(`SELECT COUNT(*) FROM sr_scripts WHERE tenant_id=? AND status='active'`),
		"running_jobs":         row(`SELECT COUNT(*) FROM sr_executions WHERE tenant_id=? AND status='running'`),
		"scheduled_jobs":       row(`SELECT COUNT(*) FROM sr_schedules WHERE tenant_id=? AND enabled=1`),
		"successful_executions": row(`SELECT COUNT(*) FROM sr_executions WHERE tenant_id=? AND status='success'`),
		"failed_executions":    row(`SELECT COUNT(*) FROM sr_executions WHERE tenant_id=? AND status='failed'`),
		"avg_execution_time":   avgTime,
		"pending_approvals":    row(`SELECT COUNT(*) FROM sr_approvals WHERE tenant_id=? AND decision='pending'`),
		"managed_endpoints":    row(`SELECT COUNT(DISTINCT target) FROM sr_executions WHERE tenant_id=?`),
	})
}

// ── Script Library ─────────────────────────────────────────────────────────

func GetSRScripts(c *gin.Context) {
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 200)
	q := "%" + c.Query("q") + "%"
	lang := c.Query("language")
	cat := c.Query("category")
	status := c.Query("status")

	query := `SELECT id,script_id,name,description,category,language,version,author,status,tags,requires_approval,last_modified,created_at FROM sr_scripts WHERE tenant_id=? AND name LIKE ?`
	args := []interface{}{tid, q}
	if lang != "" {
		query += " AND language=?"
		args = append(args, lang)
	}
	if cat != "" {
		query += " AND category=?"
		args = append(args, cat)
	}
	if status != "" {
		query += " AND status=?"
		args = append(args, status)
	}
	query += " ORDER BY last_modified DESC LIMIT ?"
	args = append(args, limit)

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()
	out := []map[string]interface{}{}
	for rows.Next() {
		var id int
		var sid, name, desc, cat2, lang2, ver, author, st, tags string
		var reqApproval int
		var lastMod, createdAt time.Time
		rows.Scan(&id, &sid, &name, &desc, &cat2, &lang2, &ver, &author, &st, &tags, &reqApproval, &lastMod, &createdAt)
		out = append(out, map[string]interface{}{
			"id": id, "script_id": sid, "name": name, "description": desc,
			"category": cat2, "language": lang2, "version": ver, "author": author,
			"status": st, "tags": tags, "requires_approval": reqApproval == 1,
			"last_modified": lastMod, "created_at": createdAt,
		})
	}
	c.JSON(http.StatusOK, out)
}

func GetSRScript(c *gin.Context) {
	tid := tenantIDFromContext(c)
	id, _ := strconv.Atoi(c.Param("id"))
	var sid, name, desc, cat, lang, ver, author, st, content, tags, params string
	var reqApproval, isSigned int
	var lastMod, createdAt time.Time
	err := database.DB.QueryRow(
		`SELECT script_id,name,description,category,language,version,author,status,content,tags,parameters,requires_approval,is_signed,last_modified,created_at FROM sr_scripts WHERE id=? AND tenant_id=?`,
		id, tid,
	).Scan(&sid, &name, &desc, &cat, &lang, &ver, &author, &st, &content, &tags, &params, &reqApproval, &isSigned, &lastMod, &createdAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id": id, "script_id": sid, "name": name, "description": desc,
		"category": cat, "language": lang, "version": ver, "author": author,
		"status": st, "content": content, "tags": tags, "parameters": params,
		"requires_approval": reqApproval == 1, "is_signed": isSigned == 1,
		"last_modified": lastMod, "created_at": createdAt,
	})
}

func PostSRScript(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var b struct {
		Name            string `json:"name"`
		Description     string `json:"description"`
		Category        string `json:"category"`
		Language        string `json:"language"`
		Version         string `json:"version"`
		Author          string `json:"author"`
		Content         string `json:"content"`
		Tags            string `json:"tags"`
		Parameters      string `json:"parameters"`
		RequiresApproval bool  `json:"requires_approval"`
	}
	if err := c.ShouldBindJSON(&b); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if b.Category == "" { b.Category = "general" }
	if b.Language == "" { b.Language = "bash" }
	if b.Version == "" { b.Version = "1.0.0" }
	if b.Author == "" { b.Author = actor }
	if b.Tags == "" { b.Tags = "[]" }
	if b.Parameters == "" { b.Parameters = "[]" }
	scriptID := fmt.Sprintf("SCR-%04d-%d", tid, time.Now().UnixMilli()%100000)
	reqApproval := 0
	if b.RequiresApproval { reqApproval = 1 }
	res, _ := database.DB.Exec(
		`INSERT INTO sr_scripts (tenant_id,script_id,name,description,category,language,version,author,content,tags,parameters,requires_approval) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		tid, scriptID, b.Name, b.Description, b.Category, b.Language, b.Version, b.Author, b.Content, b.Tags, b.Parameters, reqApproval,
	)
	id, _ := res.LastInsertId()
	srAudit(tid, scriptID, b.Name, "created", actor, fmt.Sprintf("Language: %s, Category: %s", b.Language, b.Category))
	c.JSON(http.StatusOK, gin.H{"id": id, "script_id": scriptID})
}

func PatchSRScript(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id, _ := strconv.Atoi(c.Param("id"))
	var b map[string]interface{}
	if err := c.ShouldBindJSON(&b); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var sid, name string
	database.DB.QueryRow(`SELECT script_id,name FROM sr_scripts WHERE id=? AND tenant_id=?`, id, tid).Scan(&sid, &name)
	if content, ok := b["content"].(string); ok {
		database.DB.Exec(`UPDATE sr_scripts SET content=?,last_modified=CURRENT_TIMESTAMP WHERE id=? AND tenant_id=?`, content, id, tid)
	}
	if status, ok := b["status"].(string); ok {
		database.DB.Exec(`UPDATE sr_scripts SET status=?,last_modified=CURRENT_TIMESTAMP WHERE id=? AND tenant_id=?`, status, id, tid)
		srAudit(tid, sid, name, "status_changed", actor, fmt.Sprintf("New status: %s", status))
	}
	if ver, ok := b["version"].(string); ok {
		database.DB.Exec(`UPDATE sr_scripts SET version=?,last_modified=CURRENT_TIMESTAMP WHERE id=? AND tenant_id=?`, ver, id, tid)
	}
	srAudit(tid, sid, name, "modified", actor, "Script content updated")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func DeleteSRScript(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id, _ := strconv.Atoi(c.Param("id"))
	var sid, name string
	database.DB.QueryRow(`SELECT script_id,name FROM sr_scripts WHERE id=? AND tenant_id=?`, id, tid).Scan(&sid, &name)
	database.DB.Exec(`DELETE FROM sr_scripts WHERE id=? AND tenant_id=?`, id, tid)
	srAudit(tid, sid, name, "deleted", actor, "Script deleted from library")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── Execute ────────────────────────────────────────────────────────────────

func PostSRExecute(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var b struct {
		ScriptID      string          `json:"script_id"`
		ScriptName    string          `json:"script_name"`
		Target        string          `json:"target"`
		TargetCount   int             `json:"target_count"`
		RunAs         string          `json:"run_as"`
		TriggerSource string          `json:"trigger_source"`
		Parameters    json.RawMessage `json:"parameters"`
		RequireApproval bool          `json:"require_approval"`
	}
	if err := c.ShouldBindJSON(&b); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if b.RunAs == "" { b.RunAs = "system" }
	if b.TriggerSource == "" { b.TriggerSource = "manual" }
	if b.TargetCount < 1 { b.TargetCount = 1 }
	params := "{}"
	if b.Parameters != nil { params = string(b.Parameters) }

	execID := fmt.Sprintf("EXEC-%04d-%d", tid, time.Now().UnixMilli()%1000000)

	needsApproval := b.RequireApproval || b.RunAs == "root" || b.RunAs == "administrator" || b.TargetCount > 10
	if needsApproval {
		res, _ := database.DB.Exec(
			`INSERT INTO sr_approvals (tenant_id,execution_id,script_id,script_name,target,run_as,requested_by,reason) VALUES (?,?,?,?,?,?,?,?)`,
			tid, execID, b.ScriptID, b.ScriptName, b.Target, b.RunAs, actor, "Execution requires approval",
		)
		appID, _ := res.LastInsertId()
		srAudit(tid, b.ScriptID, b.ScriptName, "approval_required", actor, fmt.Sprintf("Target: %s, RunAs: %s", b.Target, b.RunAs))
		c.JSON(http.StatusOK, gin.H{"execution_id": execID, "approval_required": true, "approval_id": appID})
		return
	}

	database.DB.Exec(
		`INSERT INTO sr_executions (tenant_id,execution_id,script_id,script_name,target,target_count,status,trigger_source,run_as,parameters,executed_by) VALUES (?,?,?,?,?,?,'running',?,?,?,?)`,
		tid, execID, b.ScriptID, b.ScriptName, b.Target, b.TargetCount, b.TriggerSource, b.RunAs, params, actor,
	)
	srAudit(tid, b.ScriptID, b.ScriptName, "executed", actor, fmt.Sprintf("Target: %s, RunAs: %s", b.Target, b.RunAs))

	// Simulate execution completion
	go func() {
		time.Sleep(2 * time.Second)
		execTime := 1200 + (time.Now().UnixMilli() % 8000)
		database.DB.Exec(
			`UPDATE sr_executions SET status='success',exit_code=0,execution_time=?,stdout='Execution completed successfully.\nAll tasks finished without errors.',completed_at=CURRENT_TIMESTAMP WHERE execution_id=? AND tenant_id=?`,
			execTime, execID, tid,
		)
	}()

	c.JSON(http.StatusOK, gin.H{"execution_id": execID, "approval_required": false, "status": "running"})
}

// ── Execution History ──────────────────────────────────────────────────────

func GetSRExecutions(c *gin.Context) {
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 100)
	status := c.Query("status")
	script := c.Query("script_id")

	query := `SELECT id,execution_id,script_id,script_name,target,target_count,status,exit_code,execution_time,trigger_source,run_as,executed_by,started_at,completed_at FROM sr_executions WHERE tenant_id=?`
	args := []interface{}{tid}
	if status != "" {
		query += " AND status=?"
		args = append(args, status)
	}
	if script != "" {
		query += " AND script_id=?"
		args = append(args, script)
	}
	query += " ORDER BY started_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()
	out := []map[string]interface{}{}
	for rows.Next() {
		var id, targetCount int
		var execID, scriptID, scriptName, target, st, trigSrc, runAs, execBy string
		var exitCode, execTime *int
		var startedAt time.Time
		var completedAt *time.Time
		rows.Scan(&id, &execID, &scriptID, &scriptName, &target, &targetCount, &st, &exitCode, &execTime, &trigSrc, &runAs, &execBy, &startedAt, &completedAt)
		out = append(out, map[string]interface{}{
			"id": id, "execution_id": execID, "script_id": scriptID, "script_name": scriptName,
			"target": target, "target_count": targetCount, "status": st, "exit_code": exitCode,
			"execution_time": execTime, "trigger_source": trigSrc, "run_as": runAs,
			"executed_by": execBy, "started_at": startedAt, "completed_at": completedAt,
		})
	}
	c.JSON(http.StatusOK, out)
}

func GetSRExecution(c *gin.Context) {
	tid := tenantIDFromContext(c)
	id, _ := strconv.Atoi(c.Param("id"))
	var execID, scriptID, scriptName, target, st, stdout, stderr, trigSrc, runAs, execBy string
	var targetCount int
	var exitCode, execTime *int
	var startedAt time.Time
	var completedAt *time.Time
	var params string
	err := database.DB.QueryRow(
		`SELECT execution_id,script_id,script_name,target,target_count,status,exit_code,stdout,stderr,execution_time,trigger_source,run_as,parameters,executed_by,started_at,completed_at FROM sr_executions WHERE id=? AND tenant_id=?`,
		id, tid,
	).Scan(&execID, &scriptID, &scriptName, &target, &targetCount, &st, &exitCode, &stdout, &stderr, &execTime, &trigSrc, &runAs, &params, &execBy, &startedAt, &completedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"execution_id": execID, "script_id": scriptID, "script_name": scriptName,
		"target": target, "target_count": targetCount, "status": st, "exit_code": exitCode,
		"stdout": stdout, "stderr": stderr, "execution_time": execTime,
		"trigger_source": trigSrc, "run_as": runAs, "parameters": params,
		"executed_by": execBy, "started_at": startedAt, "completed_at": completedAt,
	})
}

// ── AI Assistant ───────────────────────────────────────────────────────────

func PostSRAI(c *gin.Context) {
	var b struct {
		Action   string `json:"action"`
		Language string `json:"language"`
		Content  string `json:"content"`
		Prompt   string `json:"prompt"`
		TargetOS string `json:"target_os"`
	}
	if err := c.ShouldBindJSON(&b); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var prompt string
	switch b.Action {
	case "generate":
		prompt = fmt.Sprintf(`You are a cybersecurity script expert. Generate a %s script for: %s. Target OS: %s. Requirements: (1) Production-safe with error handling, (2) Include parameter validation, (3) Add inline comments for critical sections, (4) Return exit code 0 on success, non-zero on failure. Output JSON with fields: script (the full code), description (what it does), parameters (array of {name, type, description, required, default}), warnings (array of strings about risks).`, b.Language, b.Prompt, b.TargetOS)
	case "explain":
		prompt = fmt.Sprintf(`Analyze this %s script and explain it clearly: %s. Output JSON with: summary (what the script does), step_by_step (array of {line_range, description}), risks (array of potential risks), dependencies (external tools or permissions needed), suggestions (improvements).`, b.Language, b.Content)
	case "optimize":
		prompt = fmt.Sprintf(`Optimize this %s script for performance, readability and security: %s. Output JSON with: optimized_script (improved code), changes (array of {description, reason}), performance_improvement (estimated %%), security_improvements (array of strings).`, b.Language, b.Content)
	case "detect_unsafe":
		prompt = fmt.Sprintf(`Security audit this %s script for dangerous or unsafe commands: %s. Output JSON with: risk_level (low/medium/high/critical), unsafe_commands (array of {command, line, reason, severity}), overall_assessment (string), allow_execution (boolean), remediation (string).`, b.Language, b.Content)
	case "convert":
		prompt = fmt.Sprintf(`Convert this script to %s: %s. Output JSON with: converted_script (full code in target language), notes (array of conversion notes), equivalence (percentage of functional equivalence achieved).`, b.Language, b.Content)
	default:
		prompt = fmt.Sprintf(`Suggest improvements for this script: %s. Output JSON with: suggestions (array of {title, description, priority}), refactored_script (improved version).`, b.Content)
	}

	resp, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"action": b.Action, "result": resp})
}

// ── Schedules ─────────────────────────────────────────────────────────────

func GetSRSchedules(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(
		`SELECT id,name,script_id,script_name,schedule_type,cron_expr,target,run_as,enabled,last_run,next_run,created_by,created_at FROM sr_schedules WHERE tenant_id=? ORDER BY created_at DESC`,
		tid,
	)
	if err != nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()
	out := []map[string]interface{}{}
	for rows.Next() {
		var id int
		var name, sid, sname, schedType, target, runAs, createdBy string
		var cronExpr *string
		var enabled int
		var lastRun, nextRun *time.Time
		var createdAt time.Time
		rows.Scan(&id, &name, &sid, &sname, &schedType, &cronExpr, &target, &runAs, &enabled, &lastRun, &nextRun, &createdBy, &createdAt)
		out = append(out, map[string]interface{}{
			"id": id, "name": name, "script_id": sid, "script_name": sname,
			"schedule_type": schedType, "cron_expr": cronExpr, "target": target,
			"run_as": runAs, "enabled": enabled == 1, "last_run": lastRun, "next_run": nextRun,
			"created_by": createdBy, "created_at": createdAt,
		})
	}
	c.JSON(http.StatusOK, out)
}

func PostSRSchedule(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var b struct {
		Name         string `json:"name"`
		ScriptID     string `json:"script_id"`
		ScriptName   string `json:"script_name"`
		ScheduleType string `json:"schedule_type"`
		CronExpr     string `json:"cron_expr"`
		Target       string `json:"target"`
		RunAs        string `json:"run_as"`
		Parameters   string `json:"parameters"`
	}
	if err := c.ShouldBindJSON(&b); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if b.ScheduleType == "" { b.ScheduleType = "once" }
	if b.RunAs == "" { b.RunAs = "system" }
	if b.Parameters == "" { b.Parameters = "{}" }
	nextRun := time.Now().Add(time.Hour)
	res, _ := database.DB.Exec(
		`INSERT INTO sr_schedules (tenant_id,name,script_id,script_name,schedule_type,cron_expr,target,run_as,parameters,next_run,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		tid, b.Name, b.ScriptID, b.ScriptName, b.ScheduleType, b.CronExpr, b.Target, b.RunAs, b.Parameters, nextRun, actor,
	)
	id, _ := res.LastInsertId()
	srAudit(tid, b.ScriptID, b.ScriptName, "scheduled", actor, fmt.Sprintf("Schedule: %s, Target: %s", b.ScheduleType, b.Target))
	c.JSON(http.StatusOK, gin.H{"id": id})
}

func PatchSRSchedule(c *gin.Context) {
	tid := tenantIDFromContext(c)
	id, _ := strconv.Atoi(c.Param("id"))
	var b struct {
		Enabled *bool `json:"enabled"`
	}
	c.ShouldBindJSON(&b)
	if b.Enabled != nil {
		en := 0
		if *b.Enabled { en = 1 }
		database.DB.Exec(`UPDATE sr_schedules SET enabled=? WHERE id=? AND tenant_id=?`, en, id, tid)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func DeleteSRSchedule(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id, _ := strconv.Atoi(c.Param("id"))
	var sid, sname string
	database.DB.QueryRow(`SELECT script_id,script_name FROM sr_schedules WHERE id=? AND tenant_id=?`, id, tid).Scan(&sid, &sname)
	database.DB.Exec(`DELETE FROM sr_schedules WHERE id=? AND tenant_id=?`, id, tid)
	srAudit(tid, sid, sname, "schedule_deleted", actor, "Scheduled job removed")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ── Approvals ─────────────────────────────────────────────────────────────

func GetSRApprovals(c *gin.Context) {
	tid := tenantIDFromContext(c)
	decision := c.Query("decision")
	if decision == "" { decision = "pending" }
	rows, err := database.DB.Query(
		`SELECT id,execution_id,script_id,script_name,target,run_as,requested_by,reason,decision,decided_by,decided_at,created_at FROM sr_approvals WHERE tenant_id=? AND decision=? ORDER BY created_at DESC`,
		tid, decision,
	)
	if err != nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()
	out := []map[string]interface{}{}
	for rows.Next() {
		var id int
		var execID, sid, sname, target, runAs, requestedBy, reason, dec string
		var decidedBy *string
		var decidedAt *time.Time
		var createdAt time.Time
		rows.Scan(&id, &execID, &sid, &sname, &target, &runAs, &requestedBy, &reason, &dec, &decidedBy, &decidedAt, &createdAt)
		out = append(out, map[string]interface{}{
			"id": id, "execution_id": execID, "script_id": sid, "script_name": sname,
			"target": target, "run_as": runAs, "requested_by": requestedBy, "reason": reason,
			"decision": dec, "decided_by": decidedBy, "decided_at": decidedAt, "created_at": createdAt,
		})
	}
	c.JSON(http.StatusOK, out)
}

func PostSRApprove(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id, _ := strconv.Atoi(c.Param("id"))
	var b struct {
		Decision string `json:"decision"`
		Notes    string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&b); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var execID, sid, sname, target, runAs string
	database.DB.QueryRow(`SELECT execution_id,script_id,script_name,target,run_as FROM sr_approvals WHERE id=? AND tenant_id=?`, id, tid).Scan(&execID, &sid, &sname, &target, &runAs)
	database.DB.Exec(
		`UPDATE sr_approvals SET decision=?,decided_by=?,decided_at=CURRENT_TIMESTAMP WHERE id=? AND tenant_id=?`,
		b.Decision, actor, id, tid,
	)
	if b.Decision == "approve" {
		database.DB.Exec(
			`INSERT INTO sr_executions (tenant_id,execution_id,script_id,script_name,target,target_count,status,trigger_source,run_as,parameters,executed_by,approval_id) VALUES (?,?,?,?,'approved',1,'running','manual',?,?,?,?)`,
			tid, execID, sid, sname, runAs, "{}", actor, id,
		)
		srAudit(tid, sid, sname, "approved", actor, fmt.Sprintf("Execution %s approved and started", execID))
	} else {
		srAudit(tid, sid, sname, "rejected", actor, fmt.Sprintf("Execution %s rejected", execID))
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "decision": b.Decision, "execution_id": execID})
}

// ── Analytics ─────────────────────────────────────────────────────────────

func GetSRAnalytics(c *gin.Context) {
	tid := tenantIDFromContext(c)
	row := func(q string) int {
		var n int
		database.DB.QueryRow(q, tid).Scan(&n)
		return n
	}

	type scriptCount struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	topScripts := []scriptCount{}
	rows, _ := database.DB.Query(
		`SELECT script_name,COUNT(*) c FROM sr_executions WHERE tenant_id=? GROUP BY script_name ORDER BY c DESC LIMIT 5`, tid,
	)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var s scriptCount
			rows.Scan(&s.Name, &s.Count)
			topScripts = append(topScripts, s)
		}
	}

	type catCount struct {
		Category string `json:"category"`
		Count    int    `json:"count"`
	}
	byCategory := []catCount{}
	rows2, _ := database.DB.Query(
		`SELECT category,COUNT(*) c FROM sr_scripts WHERE tenant_id=? GROUP BY category ORDER BY c DESC`, tid,
	)
	if rows2 != nil {
		defer rows2.Close()
		for rows2.Next() {
			var r catCount
			rows2.Scan(&r.Category, &r.Count)
			byCategory = append(byCategory, r)
		}
	}

	total := row(`SELECT COUNT(*) FROM sr_executions WHERE tenant_id=?`)
	success := row(`SELECT COUNT(*) FROM sr_executions WHERE tenant_id=? AND status='success'`)
	failed := row(`SELECT COUNT(*) FROM sr_executions WHERE tenant_id=? AND status='failed'`)
	successRate := 0
	if total > 0 { successRate = success * 100 / total }

	avgTime := 0
	database.DB.QueryRow(`SELECT COALESCE(AVG(execution_time),0) FROM sr_executions WHERE tenant_id=? AND execution_time IS NOT NULL`, tid).Scan(&avgTime)

	trend := []map[string]interface{}{}
	for i := 6; i >= 0; i-- {
		d := time.Now().AddDate(0, 0, -i)
		dateStr := d.Format("2006-01-02")
		var cnt int
		database.DB.QueryRow(`SELECT COUNT(*) FROM sr_executions WHERE tenant_id=? AND DATE(started_at)=?`, tid, dateStr).Scan(&cnt)
		trend = append(trend, map[string]interface{}{"date": dateStr, "count": cnt})
	}

	c.JSON(http.StatusOK, gin.H{
		"total_executions":    total,
		"successful":          success,
		"failed":              failed,
		"success_rate":        successRate,
		"avg_execution_time":  avgTime,
		"total_scripts":       row(`SELECT COUNT(*) FROM sr_scripts WHERE tenant_id=?`),
		"active_scripts":      row(`SELECT COUNT(*) FROM sr_scripts WHERE tenant_id=? AND status='active'`),
		"automation_time_saved_hours": (success * avgTime) / 3600000,
		"most_executed":       topScripts,
		"by_category":         byCategory,
		"execution_trend":     trend,
	})
}

// ── Audit ─────────────────────────────────────────────────────────────────

func GetSRAudit(c *gin.Context) {
	tid := tenantIDFromContext(c)
	limit := parseLimit(c, 200)
	rows, err := database.DB.Query(
		`SELECT id,action,script_id,script_name,actor,details,created_at FROM sr_audit WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?`,
		tid, limit,
	)
	if err != nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer rows.Close()
	out := []map[string]interface{}{}
	for rows.Next() {
		var id int
		var action, scriptName, actor string
		var scriptID, details *string
		var createdAt time.Time
		rows.Scan(&id, &action, &scriptID, &scriptName, &actor, &details, &createdAt)
		out = append(out, map[string]interface{}{
			"id": id, "action": action, "script_id": scriptID, "script_name": scriptName,
			"actor": actor, "details": details, "created_at": createdAt,
		})
	}
	c.JSON(http.StatusOK, out)
}

// ── Reports ───────────────────────────────────────────────────────────────

func PostSRReport(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var b struct {
		ReportType string `json:"report_type"`
	}
	c.ShouldBindJSON(&b)
	if b.ReportType == "" { b.ReportType = "execution" }

	row := func(q string) int {
		var n int
		database.DB.QueryRow(q, tid).Scan(&n)
		return n
	}
	total := row(`SELECT COUNT(*) FROM sr_executions WHERE tenant_id=?`)
	success := row(`SELECT COUNT(*) FROM sr_executions WHERE tenant_id=? AND status='success'`)
	failed := row(`SELECT COUNT(*) FROM sr_executions WHERE tenant_id=? AND status='failed'`)
	successRate := 0
	if total > 0 { successRate = success * 100 / total }

	titles := map[string]string{
		"execution":   "Script Execution Report",
		"automation":  "Automation Report",
		"failure":     "Failure Analysis Report",
		"audit":       "Script Audit Report",
		"compliance":  "Compliance Report",
	}
	title, ok := titles[b.ReportType]
	if !ok { title = "Script Runner Report" }

	srAudit(tid, "", "System", "report_generated", actor, fmt.Sprintf("Report: %s", b.ReportType))
	c.JSON(http.StatusOK, gin.H{
		"title":             title,
		"report_type":       b.ReportType,
		"generated_at":      time.Now(),
		"generated_by":      actor,
		"classification":    "CONFIDENTIAL",
		"executive_summary": fmt.Sprintf("During the reporting period, %d script executions were recorded with a %d%% success rate. %d executions completed successfully, %d failed. Automation saves an estimated 120+ analyst-hours per week.", total, successRate, success, failed),
		"key_metrics": map[string]interface{}{
			"total_executions": total,
			"success_rate":     successRate,
			"failed":           failed,
			"total_scripts":    row(`SELECT COUNT(*) FROM sr_scripts WHERE tenant_id=?`),
			"scheduled_jobs":   row(`SELECT COUNT(*) FROM sr_schedules WHERE tenant_id=?`),
		},
		"recommendations": []string{
			"Enable script signing for all production scripts",
			"Implement approval workflow for privileged executions",
			"Schedule regular audit reviews of high-frequency scripts",
			"Enable secret vault integration for credential management",
		},
	})
}
