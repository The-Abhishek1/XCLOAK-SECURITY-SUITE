package api

import (
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"xcloak-platform/database"
	"xcloak-platform/services"
)

func InitSTETables() { createSTETables() }

func createSTETables() {
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS ste_tasks (
		id                  SERIAL PRIMARY KEY,
		tenant_id           TEXT NOT NULL,
		task_id             TEXT NOT NULL,
		name                TEXT NOT NULL,
		description         TEXT,
		category            TEXT NOT NULL DEFAULT 'security_operations',
		task_type           TEXT NOT NULL DEFAULT 'script_execution',
		script_language     TEXT,
		status              TEXT NOT NULL DEFAULT 'active',
		owner               TEXT,
		priority            TEXT NOT NULL DEFAULT 'medium',
		schedule_type       TEXT NOT NULL DEFAULT 'cron',
		cron_expr           TEXT,
		schedule_config     TEXT DEFAULT '{}',
		target_type         TEXT NOT NULL DEFAULT 'all',
		target_ids          TEXT DEFAULT '[]',
		trigger_conditions  TEXT DEFAULT '[]',
		max_runtime         INTEGER DEFAULT 3600,
		retry_attempts      INTEGER DEFAULT 3,
		retry_delay         INTEGER DEFAULT 60,
		timeout             INTEGER DEFAULT 300,
		parallel            BOOLEAN DEFAULT FALSE,
		concurrency_limit   INTEGER DEFAULT 5,
		dependencies        TEXT DEFAULT '[]',
		requires_approval   BOOLEAN DEFAULT FALSE,
		approval_policy     TEXT,
		tags                TEXT DEFAULT '[]',
		enabled             BOOLEAN DEFAULT TRUE,
		last_run_at         TIMESTAMP,
		next_run_at         TIMESTAMP,
		run_count           INTEGER DEFAULT 0,
		success_count       INTEGER DEFAULT 0,
		failure_count       INTEGER DEFAULT 0,
		avg_duration        INTEGER DEFAULT 0,
		created_by          TEXT NOT NULL DEFAULT 'system',
		created_at          TIMESTAMP DEFAULT NOW(),
		updated_at          TIMESTAMP DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS ste_executions (
		id              SERIAL PRIMARY KEY,
		tenant_id       TEXT NOT NULL,
		execution_id    TEXT NOT NULL,
		task_id         TEXT NOT NULL,
		task_name       TEXT NOT NULL,
		start_time      TIMESTAMP DEFAULT NOW(),
		end_time        TIMESTAMP,
		duration        INTEGER,
		status          TEXT NOT NULL DEFAULT 'running',
		trigger         TEXT NOT NULL DEFAULT 'scheduled',
		executed_by     TEXT NOT NULL DEFAULT 'system',
		target_count    INTEGER DEFAULT 0,
		success_count   INTEGER DEFAULT 0,
		failure_count   INTEGER DEFAULT 0,
		output_logs     TEXT,
		error_message   TEXT,
		exit_code       INTEGER,
		created_at      TIMESTAMP DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS ste_approvals (
		id              SERIAL PRIMARY KEY,
		tenant_id       TEXT NOT NULL,
		task_id         TEXT NOT NULL,
		task_name       TEXT NOT NULL,
		execution_id    TEXT,
		requester       TEXT NOT NULL,
		approver        TEXT,
		status          TEXT NOT NULL DEFAULT 'pending',
		reason          TEXT,
		decision_note   TEXT,
		policy          TEXT NOT NULL DEFAULT 'manual',
		decided_at      TIMESTAMP,
		expires_at      TIMESTAMP,
		created_at      TIMESTAMP DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS ste_notifications (
		id           SERIAL PRIMARY KEY,
		tenant_id    TEXT NOT NULL,
		task_id      TEXT,
		task_name    TEXT,
		event_type   TEXT NOT NULL,
		message      TEXT NOT NULL,
		severity     TEXT NOT NULL DEFAULT 'info',
		read         BOOLEAN DEFAULT FALSE,
		created_at   TIMESTAMP DEFAULT NOW()
	)`)
	database.DB.Exec(`CREATE TABLE IF NOT EXISTS ste_audit (
		id          SERIAL PRIMARY KEY,
		tenant_id   TEXT NOT NULL,
		task_id     TEXT,
		task_name   TEXT,
		action      TEXT NOT NULL,
		actor       TEXT NOT NULL,
		details     TEXT,
		created_at  TIMESTAMP DEFAULT NOW()
	)`)
}

func steAudit(tid int, taskID, taskName, action, actor, details string) {
	database.DB.Exec(`INSERT INTO ste_audit (tenant_id,task_id,task_name,action,actor,details)
		VALUES ($1,$2,$3,$4,$5,$6)`, tid, taskID, taskName, action, actor, details)
}

func steNotify(tid int, taskID, taskName, eventType, message, severity string) {
	database.DB.Exec(`INSERT INTO ste_notifications (tenant_id,task_id,task_name,event_type,message,severity)
		VALUES ($1,$2,$3,$4,$5,$6)`, tid, taskID, taskName, eventType, message, severity)
}

// GET /api/ste/dashboard
func GetSTEDashboard(c *gin.Context) {
	tid := tenantIDFromContext(c)
	count := func(where string, args ...any) int {
		var n int
		database.DB.QueryRow(`SELECT COUNT(*) FROM ste_tasks WHERE tenant_id=$1`+where, append([]any{tid}, args...)...).Scan(&n)
		return n
	}
	countExec := func(where string, args ...any) int {
		var n int
		database.DB.QueryRow(`SELECT COUNT(*) FROM ste_executions WHERE tenant_id=$1`+where, append([]any{tid}, args...)...).Scan(&n)
		return n
	}
	var avgDuration float64
	database.DB.QueryRow(`SELECT COALESCE(AVG(duration),0) FROM ste_executions WHERE tenant_id=$1 AND status='completed'`, tid).Scan(&avgDuration)
	var pendingApprovals int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ste_approvals WHERE tenant_id=$1 AND status='pending'`, tid).Scan(&pendingApprovals)
	var unreadNotifications int
	database.DB.QueryRow(`SELECT COUNT(*) FROM ste_notifications WHERE tenant_id=$1 AND read=FALSE`, tid).Scan(&unreadNotifications)

	// Upcoming executions (next 5)
	rows, _ := database.DB.Query(`SELECT task_id,name,next_run_at FROM ste_tasks WHERE tenant_id=$1 AND enabled=TRUE AND next_run_at IS NOT NULL ORDER BY next_run_at ASC LIMIT 5`, tid)
	type upcoming struct {
		TaskID    string `json:"task_id"`
		Name      string `json:"name"`
		NextRunAt string `json:"next_run_at"`
	}
	upcomingList := []upcoming{}
	if rows != nil {
		for rows.Next() {
			var u upcoming
			var t time.Time
			rows.Scan(&u.TaskID, &u.Name, &t)
			u.NextRunAt = t.Format(time.RFC3339)
			upcomingList = append(upcomingList, u)
		}
		rows.Close()
	}

	// Recent failures
	type recentFail struct {
		TaskName  string `json:"task_name"`
		Status    string `json:"status"`
		StartTime string `json:"start_time"`
	}
	failRows, _ := database.DB.Query(`SELECT task_name,status,start_time FROM ste_executions WHERE tenant_id=$1 AND status='failed' ORDER BY start_time DESC LIMIT 5`, tid)
	recentFails := []recentFail{}
	if failRows != nil {
		for failRows.Next() {
			var f recentFail
			var t time.Time
			failRows.Scan(&f.TaskName, &f.Status, &t)
			f.StartTime = t.Format(time.RFC3339)
			recentFails = append(recentFails, f)
		}
		failRows.Close()
	}

	c.JSON(http.StatusOK, gin.H{
		"total_tasks":            count(``),
		"active_tasks":           count(` AND status='active' AND enabled=TRUE`),
		"paused_tasks":           count(` AND enabled=FALSE`),
		"running_tasks":          countExec(` AND status='running'`),
		"failed_tasks":           count(` AND failure_count>0`),
		"completed_executions":   countExec(` AND status='completed'`),
		"failed_executions":      countExec(` AND status='failed'`),
		"total_executions":       countExec(``),
		"avg_execution_time":     avgDuration,
		"pending_approvals":      pendingApprovals,
		"unread_notifications":   unreadNotifications,
		"upcoming_executions":    upcomingList,
		"recent_failures":        recentFails,
	})
}

// GET /api/ste/tasks
func GetSTETasks(c *gin.Context) {
	tid := tenantIDFromContext(c)
	search := c.Query("search")
	category := c.Query("category")
	status := c.Query("status")
	taskType := c.Query("task_type")
	owner := c.Query("owner")
	scheduleType := c.Query("schedule_type")
	tag := c.Query("tag")
	limit := parseLimit(c, 200)

	q := `SELECT id,task_id,name,description,category,task_type,script_language,status,owner,priority,
		schedule_type,cron_expr,schedule_config,target_type,target_ids,trigger_conditions,
		max_runtime,retry_attempts,retry_delay,timeout,parallel,concurrency_limit,
		dependencies,requires_approval,approval_policy,tags,enabled,
		last_run_at,next_run_at,run_count,success_count,failure_count,avg_duration,
		created_by,created_at,updated_at
		FROM ste_tasks WHERE tenant_id=$1`
	args := []any{tid}
	i := 2

	if category != "" {
		q += fmt.Sprintf(` AND category=$%d`, i); args = append(args, category); i++
	}
	if status != "" {
		q += fmt.Sprintf(` AND status=$%d`, i); args = append(args, status); i++
	}
	if taskType != "" {
		q += fmt.Sprintf(` AND task_type=$%d`, i); args = append(args, taskType); i++
	}
	if owner != "" {
		q += fmt.Sprintf(` AND owner ILIKE $%d`, i); args = append(args, "%"+owner+"%"); i++
	}
	if scheduleType != "" {
		q += fmt.Sprintf(` AND schedule_type=$%d`, i); args = append(args, scheduleType); i++
	}
	if tag != "" {
		q += fmt.Sprintf(` AND tags LIKE $%d`, i); args = append(args, "%"+tag+"%"); i++
	}
	if search != "" {
		q += fmt.Sprintf(` AND (name ILIKE $%d OR task_id ILIKE $%d OR description ILIKE $%d OR owner ILIKE $%d)`, i, i, i, i)
		args = append(args, "%"+search+"%"); i++
	}
	q += fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d`, i)
	args = append(args, limit)

	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	tasks := []map[string]any{}
	for rows.Next() {
		var (
			id, maxRuntime, retryAttempts, retryDelay, timeout, concurrencyLimit int
			runCount, successCount, failureCount, avgDuration                    int
			parallel, requiresApproval, enabled                                  bool
			taskID, name, category2, taskType2, scriptLang, status2, owner2     string
			priority, schedType, cronExpr, schedCfg, targetType                 string
			targetIDs, triggerConds, deps, approvalPolicy, tags, createdBy       string
			description                                                           string
			lastRunAt, nextRunAt                                                  *time.Time
			createdAt, updatedAt                                                  time.Time
		)
		rows.Scan(
			&id, &taskID, &name, &description, &category2, &taskType2, &scriptLang, &status2, &owner2, &priority,
			&schedType, &cronExpr, &schedCfg, &targetType, &targetIDs, &triggerConds,
			&maxRuntime, &retryAttempts, &retryDelay, &timeout, &parallel, &concurrencyLimit,
			&deps, &requiresApproval, &approvalPolicy, &tags, &enabled,
			&lastRunAt, &nextRunAt, &runCount, &successCount, &failureCount, &avgDuration,
			&createdBy, &createdAt, &updatedAt,
		)
		t := map[string]any{
			"id": id, "task_id": taskID, "name": name, "description": description,
			"category": category2, "task_type": taskType2, "script_language": scriptLang,
			"status": status2, "owner": owner2, "priority": priority,
			"schedule_type": schedType, "cron_expr": cronExpr, "schedule_config": schedCfg,
			"target_type": targetType, "target_ids": targetIDs, "trigger_conditions": triggerConds,
			"max_runtime": maxRuntime, "retry_attempts": retryAttempts, "retry_delay": retryDelay,
			"timeout": timeout, "parallel": parallel, "concurrency_limit": concurrencyLimit,
			"dependencies": deps, "requires_approval": requiresApproval, "approval_policy": approvalPolicy,
			"tags": tags, "enabled": enabled,
			"run_count": runCount, "success_count": successCount, "failure_count": failureCount,
			"avg_duration": avgDuration, "created_by": createdBy,
			"created_at": createdAt.Format(time.RFC3339), "updated_at": updatedAt.Format(time.RFC3339),
		}
		if lastRunAt != nil {
			t["last_run_at"] = lastRunAt.Format(time.RFC3339)
		}
		if nextRunAt != nil {
			t["next_run_at"] = nextRunAt.Format(time.RFC3339)
		}
		tasks = append(tasks, t)
	}
	c.JSON(http.StatusOK, tasks)
}

// GET /api/ste/tasks/:id
func GetSTETask(c *gin.Context) {
	tid := tenantIDFromContext(c)
	id := c.Param("id")
	var row map[string]any
	r := database.DB.QueryRow(`SELECT id,task_id,name,description,category,task_type,script_language,status,owner,priority,
		schedule_type,cron_expr,schedule_config,target_type,target_ids,trigger_conditions,
		max_runtime,retry_attempts,retry_delay,timeout,parallel,concurrency_limit,
		dependencies,requires_approval,approval_policy,tags,enabled,
		last_run_at,next_run_at,run_count,success_count,failure_count,avg_duration,created_by,created_at
		FROM ste_tasks WHERE tenant_id=$1 AND id=$2`, tid, id)
	var (
		dbID, maxRuntime, retryAttempts, retryDelay, timeout, concurrencyLimit int
		runCount, successCount, failureCount, avgDuration                      int
		parallel, requiresApproval, enabled                                    bool
		taskID, name, cat, tt, sl, st, own, pri, sched, cron, scfg, tgt      string
		tids, trig, deps, apol, tags, cb, desc                                string
		lr, nr                                                                  *time.Time
		ca                                                                      time.Time
	)
	err := r.Scan(&dbID, &taskID, &name, &desc, &cat, &tt, &sl, &st, &own, &pri,
		&sched, &cron, &scfg, &tgt, &tids, &trig,
		&maxRuntime, &retryAttempts, &retryDelay, &timeout, &parallel, &concurrencyLimit,
		&deps, &requiresApproval, &apol, &tags, &enabled,
		&lr, &nr, &runCount, &successCount, &failureCount, &avgDuration, &cb, &ca)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	row = map[string]any{
		"id": dbID, "task_id": taskID, "name": name, "description": desc,
		"category": cat, "task_type": tt, "script_language": sl, "status": st,
		"owner": own, "priority": pri, "schedule_type": sched, "cron_expr": cron,
		"schedule_config": scfg, "target_type": tgt, "target_ids": tids,
		"trigger_conditions": trig, "max_runtime": maxRuntime, "retry_attempts": retryAttempts,
		"retry_delay": retryDelay, "timeout": timeout, "parallel": parallel,
		"concurrency_limit": concurrencyLimit, "dependencies": deps,
		"requires_approval": requiresApproval, "approval_policy": apol,
		"tags": tags, "enabled": enabled, "run_count": runCount,
		"success_count": successCount, "failure_count": failureCount, "avg_duration": avgDuration,
		"created_by": cb, "created_at": ca.Format(time.RFC3339),
	}
	if lr != nil {
		row["last_run_at"] = lr.Format(time.RFC3339)
	}
	if nr != nil {
		row["next_run_at"] = nr.Format(time.RFC3339)
	}
	c.JSON(http.StatusOK, row)
}

// POST /api/ste/tasks
func PostSTETask(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var b struct {
		Name               string `json:"name"`
		Description        string `json:"description"`
		Category           string `json:"category"`
		TaskType           string `json:"task_type"`
		ScriptLanguage     string `json:"script_language"`
		Owner              string `json:"owner"`
		Priority           string `json:"priority"`
		ScheduleType       string `json:"schedule_type"`
		CronExpr           string `json:"cron_expr"`
		ScheduleConfig     string `json:"schedule_config"`
		TargetType         string `json:"target_type"`
		TargetIDs          string `json:"target_ids"`
		TriggerConditions  string `json:"trigger_conditions"`
		MaxRuntime         int    `json:"max_runtime"`
		RetryAttempts      int    `json:"retry_attempts"`
		RetryDelay         int    `json:"retry_delay"`
		Timeout            int    `json:"timeout"`
		Parallel           bool   `json:"parallel"`
		ConcurrencyLimit   int    `json:"concurrency_limit"`
		Dependencies       string `json:"dependencies"`
		RequiresApproval   bool   `json:"requires_approval"`
		ApprovalPolicy     string `json:"approval_policy"`
		Tags               string `json:"tags"`
		Enabled            bool   `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&b); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if b.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name required"})
		return
	}
	setDefault := func(s, d string) string {
		if s == "" {
			return d
		}
		return s
	}
	b.Category = setDefault(b.Category, "security_operations")
	b.TaskType = setDefault(b.TaskType, "script_execution")
	b.Priority = setDefault(b.Priority, "medium")
	b.ScheduleType = setDefault(b.ScheduleType, "cron")
	b.TargetType = setDefault(b.TargetType, "all")
	b.ScheduleConfig = setDefault(b.ScheduleConfig, "{}")
	b.TargetIDs = setDefault(b.TargetIDs, "[]")
	b.TriggerConditions = setDefault(b.TriggerConditions, "[]")
	b.Dependencies = setDefault(b.Dependencies, "[]")
	b.Tags = setDefault(b.Tags, "[]")
	if b.MaxRuntime == 0 {
		b.MaxRuntime = 3600
	}
	if b.RetryAttempts == 0 {
		b.RetryAttempts = 3
	}
	if b.RetryDelay == 0 {
		b.RetryDelay = 60
	}
	if b.Timeout == 0 {
		b.Timeout = 300
	}
	if b.ConcurrencyLimit == 0 {
		b.ConcurrencyLimit = 5
	}

	taskID := fmt.Sprintf("ST-%06d", rand.Intn(999999))
	var nextRun *time.Time
	if b.CronExpr != "" {
		t := time.Now().Add(time.Hour)
		nextRun = &t
	}

	var id int
	err := database.DB.QueryRow(`INSERT INTO ste_tasks
		(tenant_id,task_id,name,description,category,task_type,script_language,status,owner,priority,
		schedule_type,cron_expr,schedule_config,target_type,target_ids,trigger_conditions,
		max_runtime,retry_attempts,retry_delay,timeout,parallel,concurrency_limit,
		dependencies,requires_approval,approval_policy,tags,enabled,next_run_at,created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)
		RETURNING id`,
		tid, taskID, b.Name, b.Description, b.Category, b.TaskType, b.ScriptLanguage, b.Owner, b.Priority,
		b.ScheduleType, b.CronExpr, b.ScheduleConfig, b.TargetType, b.TargetIDs, b.TriggerConditions,
		b.MaxRuntime, b.RetryAttempts, b.RetryDelay, b.Timeout, b.Parallel, b.ConcurrencyLimit,
		b.Dependencies, b.RequiresApproval, b.ApprovalPolicy, b.Tags, b.Enabled, nextRun, actor,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	steAudit(tid, taskID, b.Name, "created", actor, "Task created")
	c.JSON(http.StatusCreated, gin.H{"id": id, "task_id": taskID})
}

// PATCH /api/ste/tasks/:id
func PatchSTETask(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id := c.Param("id")
	var b map[string]any
	if err := c.ShouldBindJSON(&b); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Toggle enabled
	if enabled, ok := b["enabled"]; ok {
		_, err := database.DB.Exec(`UPDATE ste_tasks SET enabled=$1, updated_at=NOW() WHERE tenant_id=$2 AND id=$3`, enabled, tid, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		action := "enabled"
		if enabled == false {
			action = "disabled"
		}
		var taskID, name string
		database.DB.QueryRow(`SELECT task_id, name FROM ste_tasks WHERE id=$1`, id).Scan(&taskID, &name)
		steAudit(tid, taskID, name, action, actor, "")
		c.JSON(http.StatusOK, gin.H{"ok": true})
		return
	}

	// General update
	_, err := database.DB.Exec(`UPDATE ste_tasks SET
		name=COALESCE(NULLIF($3,''),name),
		description=COALESCE(NULLIF($4,''),description),
		owner=COALESCE(NULLIF($5,''),owner),
		priority=COALESCE(NULLIF($6,''),priority),
		cron_expr=COALESCE(NULLIF($7,''),cron_expr),
		schedule_type=COALESCE(NULLIF($8,''),schedule_type),
		requires_approval=$9,
		tags=COALESCE(NULLIF($10,''),tags),
		updated_at=NOW()
		WHERE tenant_id=$1 AND id=$2`,
		tid, id,
		b["name"], b["description"], b["owner"], b["priority"],
		b["cron_expr"], b["schedule_type"], b["requires_approval"], b["tags"],
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var taskID, name string
	database.DB.QueryRow(`SELECT task_id, name FROM ste_tasks WHERE id=$1`, id).Scan(&taskID, &name)
	steAudit(tid, taskID, name, "modified", actor, "Task updated")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DELETE /api/ste/tasks/:id
func DeleteSTETask(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id := c.Param("id")
	var taskID, name string
	database.DB.QueryRow(`SELECT task_id, name FROM ste_tasks WHERE id=$1`, id).Scan(&taskID, &name)
	database.DB.Exec(`DELETE FROM ste_tasks WHERE tenant_id=$1 AND id=$2`, tid, id)
	steAudit(tid, taskID, name, "deleted", actor, "Task deleted")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// POST /api/ste/tasks/:id/run
func PostSTERunTask(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id := c.Param("id")

	var taskID, name string
	var requiresApproval bool
	err := database.DB.QueryRow(`SELECT task_id, name, requires_approval FROM ste_tasks WHERE tenant_id=$1 AND id=$2`, tid, id).Scan(&taskID, &name, &requiresApproval)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	if requiresApproval {
		var approvalID int
		database.DB.QueryRow(`INSERT INTO ste_approvals
			(tenant_id,task_id,task_name,requester,status,policy,expires_at)
			VALUES ($1,$2,$3,$4,'pending','manual',NOW()+INTERVAL '24 hours')
			RETURNING id`, tid, taskID, name, actor).Scan(&approvalID)
		steNotify(tid, taskID, name, "approval_required", fmt.Sprintf("Task '%s' requires approval before execution", name), "warning")
		steAudit(tid, taskID, name, "approval_requested", actor, "Manual run requested approval")
		c.JSON(http.StatusAccepted, gin.H{"status": "pending_approval", "approval_id": approvalID})
		return
	}

	execID := fmt.Sprintf("EX-%08d", rand.Intn(99999999))
	var eid int
	database.DB.QueryRow(`INSERT INTO ste_executions
		(tenant_id,execution_id,task_id,task_name,status,trigger,executed_by,target_count)
		VALUES ($1,$2,$3,$4,'running','manual',$5,1) RETURNING id`, tid, execID, taskID, name, actor).Scan(&eid)
	database.DB.Exec(`UPDATE ste_tasks SET run_count=run_count+1, last_run_at=NOW(), updated_at=NOW() WHERE id=$1`, id)
	steAudit(tid, taskID, name, "executed", actor, "Manual run triggered")
	steNotify(tid, taskID, name, "task_started", fmt.Sprintf("Task '%s' started manually by %s", name, actor), "info")

	// Simulate completion in background
	go func() {
		time.Sleep(time.Duration(2+rand.Intn(8)) * time.Second)
		dur := 2000 + rand.Intn(30000)
		success := rand.Float32() > 0.1
		st := "completed"
		if !success {
			st = "failed"
		}
		database.DB.Exec(`UPDATE ste_executions SET status=$1,end_time=NOW(),duration=$2,exit_code=$3 WHERE id=$4`,
			st, dur, map[bool]int{true: 0, false: 1}[success], eid)
		if success {
			database.DB.Exec(`UPDATE ste_tasks SET success_count=success_count+1 WHERE id=$1`, id)
			steNotify(tid, taskID, name, "task_completed", fmt.Sprintf("Task '%s' completed successfully", name), "info")
		} else {
			database.DB.Exec(`UPDATE ste_tasks SET failure_count=failure_count+1 WHERE id=$1`, id)
			steNotify(tid, taskID, name, "task_failed", fmt.Sprintf("Task '%s' failed", name), "critical")
		}
	}()

	c.JSON(http.StatusOK, gin.H{"status": "running", "execution_id": execID})
}

// GET /api/ste/executions
func GetSTEExecutions(c *gin.Context) {
	tid := tenantIDFromContext(c)
	taskID := c.Query("task_id")
	status := c.Query("status")
	trigger := c.Query("trigger")
	limit := parseLimit(c, 100)

	q := `SELECT id,execution_id,task_id,task_name,start_time,end_time,duration,status,trigger,
		executed_by,target_count,success_count,failure_count,output_logs,error_message,exit_code
		FROM ste_executions WHERE tenant_id=$1`
	args := []any{tid}
	i := 2
	if taskID != "" {
		q += fmt.Sprintf(` AND task_id=$%d`, i); args = append(args, taskID); i++
	}
	if status != "" {
		q += fmt.Sprintf(` AND status=$%d`, i); args = append(args, status); i++
	}
	if trigger != "" {
		q += fmt.Sprintf(` AND trigger=$%d`, i); args = append(args, trigger); i++
	}
	q += fmt.Sprintf(` ORDER BY start_time DESC LIMIT $%d`, i)
	args = append(args, limit)

	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	execs := []map[string]any{}
	for rows.Next() {
		var (
			id, targetCount, successCount, failureCount int
			duration, exitCode                          *int
			execID, taskID2, taskName, status2          string
			trigger2, executedBy                        string
			outputLogs, errMsg                          *string
			startTime                                   time.Time
			endTime                                     *time.Time
		)
		rows.Scan(&id, &execID, &taskID2, &taskName, &startTime, &endTime, &duration, &status2,
			&trigger2, &executedBy, &targetCount, &successCount, &failureCount, &outputLogs, &errMsg, &exitCode)
		e := map[string]any{
			"id": id, "execution_id": execID, "task_id": taskID2, "task_name": taskName,
			"start_time": startTime.Format(time.RFC3339), "status": status2,
			"trigger": trigger2, "executed_by": executedBy,
			"target_count": targetCount, "success_count": successCount, "failure_count": failureCount,
		}
		if endTime != nil {
			e["end_time"] = endTime.Format(time.RFC3339)
		}
		if duration != nil {
			e["duration"] = *duration
		}
		if exitCode != nil {
			e["exit_code"] = *exitCode
		}
		if outputLogs != nil {
			e["output_logs"] = *outputLogs
		}
		if errMsg != nil {
			e["error_message"] = *errMsg
		}
		execs = append(execs, e)
	}
	c.JSON(http.StatusOK, execs)
}

// GET /api/ste/upcoming
func GetSTEUpcoming(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT task_id,name,category,task_type,next_run_at,cron_expr,owner,priority
		FROM ste_tasks WHERE tenant_id=$1 AND enabled=TRUE AND next_run_at IS NOT NULL
		ORDER BY next_run_at ASC LIMIT 50`, tid)
	if err != nil {
		c.JSON(http.StatusOK, []any{})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var taskID, name, cat, tt, cron, owner, priority string
		var nextRun time.Time
		rows.Scan(&taskID, &name, &cat, &tt, &nextRun, &cron, &owner, &priority)
		items = append(items, map[string]any{
			"task_id": taskID, "name": name, "category": cat, "task_type": tt,
			"next_run_at": nextRun.Format(time.RFC3339), "cron_expr": cron,
			"owner": owner, "priority": priority,
		})
	}
	c.JSON(http.StatusOK, items)
}

// GET /api/ste/approvals
func GetSTEApprovals(c *gin.Context) {
	tid := tenantIDFromContext(c)
	status := c.Query("status")
	q := `SELECT id,task_id,task_name,execution_id,requester,approver,status,reason,decision_note,policy,decided_at,expires_at,created_at
		FROM ste_approvals WHERE tenant_id=$1`
	args := []any{tid}
	if status != "" {
		q += ` AND status=$2`
		args = append(args, status)
	}
	q += ` ORDER BY created_at DESC LIMIT 100`
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		c.JSON(http.StatusOK, []any{})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id int
		var taskID, taskName, requester, status2, policy string
		var execID, approver, reason, decisionNote *string
		var decidedAt, expiresAt *time.Time
		var createdAt time.Time
		rows.Scan(&id, &taskID, &taskName, &execID, &requester, &approver, &status2, &reason, &decisionNote, &policy, &decidedAt, &expiresAt, &createdAt)
		it := map[string]any{
			"id": id, "task_id": taskID, "task_name": taskName,
			"requester": requester, "status": status2, "policy": policy,
			"created_at": createdAt.Format(time.RFC3339),
		}
		if execID != nil {
			it["execution_id"] = *execID
		}
		if approver != nil {
			it["approver"] = *approver
		}
		if reason != nil {
			it["reason"] = *reason
		}
		if decisionNote != nil {
			it["decision_note"] = *decisionNote
		}
		if decidedAt != nil {
			it["decided_at"] = decidedAt.Format(time.RFC3339)
		}
		if expiresAt != nil {
			it["expires_at"] = expiresAt.Format(time.RFC3339)
		}
		items = append(items, it)
	}
	c.JSON(http.StatusOK, items)
}

// POST /api/ste/approvals/:id/decide
func PostSTEApprovalDecide(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	id := c.Param("id")
	var b struct {
		Decision string `json:"decision"`
		Note     string `json:"note"`
	}
	c.ShouldBindJSON(&b)
	if b.Decision != "approved" && b.Decision != "rejected" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "decision must be approved or rejected"})
		return
	}
	_, err := database.DB.Exec(`UPDATE ste_approvals SET status=$1,approver=$2,decision_note=$3,decided_at=NOW() WHERE tenant_id=$4 AND id=$5`,
		b.Decision, actor, b.Note, tid, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var taskID, taskName string
	database.DB.QueryRow(`SELECT task_id,task_name FROM ste_approvals WHERE id=$1`, id).Scan(&taskID, &taskName)
	steAudit(tid, taskID, taskName, b.Decision, actor, b.Note)
	severity := "info"
	if b.Decision == "rejected" {
		severity = "warning"
	}
	steNotify(tid, taskID, taskName, "approval_"+b.Decision, fmt.Sprintf("Task '%s' %s by %s", taskName, b.Decision, actor), severity)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// GET /api/ste/notifications
func GetSTENotifications(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT id,task_id,task_name,event_type,message,severity,read,created_at
		FROM ste_notifications WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100`, tid)
	if err != nil {
		c.JSON(http.StatusOK, []any{})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id int
		var taskID, eventType, message, severity string
		var taskName *string
		var read bool
		var createdAt time.Time
		rows.Scan(&id, &taskID, &taskName, &eventType, &message, &severity, &read, &createdAt)
		it := map[string]any{
			"id": id, "task_id": taskID, "event_type": eventType,
			"message": message, "severity": severity, "read": read,
			"created_at": createdAt.Format(time.RFC3339),
		}
		if taskName != nil {
			it["task_name"] = *taskName
		}
		items = append(items, it)
	}
	c.JSON(http.StatusOK, items)
}

// PATCH /api/ste/notifications/read
func PatchSTENotificationsRead(c *gin.Context) {
	tid := tenantIDFromContext(c)
	database.DB.Exec(`UPDATE ste_notifications SET read=TRUE WHERE tenant_id=$1`, tid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// GET /api/ste/analytics
func GetSTEAnalytics(c *gin.Context) {
	tid := tenantIDFromContext(c)

	type catStat struct {
		Category     string  `json:"category"`
		Total        int     `json:"total"`
		SuccessRate  float64 `json:"success_rate"`
		AvgDuration  float64 `json:"avg_duration"`
	}
	rows, _ := database.DB.Query(`SELECT category,
		COUNT(*) as total,
		COALESCE(AVG(CASE WHEN status='completed' THEN 1.0 ELSE 0.0 END)*100,0) as success_rate,
		COALESCE(AVG(duration),0) as avg_duration
		FROM ste_executions WHERE tenant_id=$1
		GROUP BY category ORDER BY total DESC LIMIT 10`, tid)
	catStats := []catStat{}
	if rows != nil {
		for rows.Next() {
			var cs catStat
			rows.Scan(&cs.Category, &cs.Total, &cs.SuccessRate, &cs.AvgDuration)
			catStats = append(catStats, cs)
		}
		rows.Close()
	}

	type typeStat struct {
		TaskType  string `json:"task_type"`
		Executions int   `json:"executions"`
	}
	trows, _ := database.DB.Query(`SELECT t.task_type, COUNT(e.id) as executions
		FROM ste_tasks t LEFT JOIN ste_executions e ON e.task_id=t.task_id AND e.tenant_id=t.tenant_id
		WHERE t.tenant_id=$1 GROUP BY t.task_type ORDER BY executions DESC LIMIT 10`, tid)
	typeStats := []typeStat{}
	if trows != nil {
		for trows.Next() {
			var ts typeStat
			trows.Scan(&ts.TaskType, &ts.Executions)
			typeStats = append(typeStats, ts)
		}
		trows.Close()
	}

	var totalCompleted, totalFailed int
	var totalDuration float64
	database.DB.QueryRow(`SELECT COUNT(*) FILTER (WHERE status='completed'), COUNT(*) FILTER (WHERE status='failed'), COALESCE(AVG(duration),0) FROM ste_executions WHERE tenant_id=$1`, tid).Scan(&totalCompleted, &totalFailed, &totalDuration)
	total := totalCompleted + totalFailed
	successRate := 0.0
	if total > 0 {
		successRate = float64(totalCompleted) / float64(total) * 100
	}

	automationHours := float64(totalCompleted) * (totalDuration / 1000) / 3600

	c.JSON(http.StatusOK, gin.H{
		"total_completed":    totalCompleted,
		"total_failed":       totalFailed,
		"success_rate":       successRate,
		"avg_duration_ms":    totalDuration,
		"automation_hours":   automationHours,
		"by_category":        catStats,
		"by_task_type":       typeStats,
	})
}

// GET /api/ste/audit
func GetSTEAudit(c *gin.Context) {
	tid := tenantIDFromContext(c)
	rows, err := database.DB.Query(`SELECT id,task_id,task_name,action,actor,details,created_at
		FROM ste_audit WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 200`, tid)
	if err != nil {
		c.JSON(http.StatusOK, []any{})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id int
		var taskID, action, actor string
		var taskName, details *string
		var createdAt time.Time
		rows.Scan(&id, &taskID, &taskName, &action, &actor, &details, &createdAt)
		it := map[string]any{
			"id": id, "task_id": taskID, "action": action,
			"actor": actor, "created_at": createdAt.Format(time.RFC3339),
		}
		if taskName != nil {
			it["task_name"] = *taskName
		}
		if details != nil {
			it["details"] = *details
		}
		items = append(items, it)
	}
	c.JSON(http.StatusOK, items)
}

// POST /api/ste/ai
func PostSTEAI(c *gin.Context) {
	tid := tenantIDFromContext(c)
	db := database.DB
	var b struct {
		Action  string `json:"action"`
		Context string `json:"context"`
		TaskID  string `json:"task_id"`
	}
	c.ShouldBindJSON(&b)

	var ctx strings.Builder
	trows, _ := db.Query(`SELECT task_id, name, task_type, cron_expr, schedule_type, next_run_at, enabled,
		run_count, success_count, failure_count, avg_duration
		FROM ste_tasks WHERE tenant_id=$1 ORDER BY enabled DESC, next_run_at ASC NULLS LAST LIMIT 25`, tid)
	if trows != nil {
		ctx.WriteString("Scheduled tasks:\n")
		for trows.Next() {
			var taskID, name, taskType, cron, schedType string
			var nextRun *time.Time
			var enabled bool
			var runCount, successCount, failureCount int
			var avgDuration float64
			trows.Scan(&taskID, &name, &taskType, &cron, &schedType, &nextRun, &enabled,
				&runCount, &successCount, &failureCount, &avgDuration)
			nextRunStr := "not scheduled"
			if nextRun != nil {
				nextRunStr = nextRun.Format("Mon 15:04 UTC")
			}
			fmt.Fprintf(&ctx, "- [%s] %s (%s), cron=%q, next_run=%s, enabled=%v, runs=%d (fail=%d), avg_duration=%.0fs\n",
				taskID, name, taskType, cron, nextRunStr, enabled, runCount, failureCount, avgDuration)
		}
		trows.Close()
	}

	frows, _ := db.Query(`SELECT task_name, status, start_time FROM ste_executions
		WHERE tenant_id=$1 AND status='failed' ORDER BY start_time DESC LIMIT 8`, tid)
	if frows != nil {
		ctx.WriteString("Recent failed executions:\n")
		for frows.Next() {
			var name, status string
			var start time.Time
			frows.Scan(&name, &status, &start)
			fmt.Fprintf(&ctx, "- %s failed at %s\n", name, start.Format("2006-01-02 15:04"))
		}
		frows.Close()
	}

	if b.TaskID != "" {
		var name, desc, taskType, cron string
		err := db.QueryRow(`SELECT name, COALESCE(description,''), task_type, cron_expr FROM ste_tasks
			WHERE tenant_id=$1 AND task_id=$2`, tid, b.TaskID).Scan(&name, &desc, &taskType, &cron)
		if err == nil {
			fmt.Fprintf(&ctx, "\nFocus task: %s (%s), cron=%q, description=%q\n", name, taskType, cron, desc)
		}
	}
	if b.Context != "" {
		fmt.Fprintf(&ctx, "\nAdditional context: %s\n", b.Context)
	}
	stectx := ctx.String()

	var task string
	switch b.Action {
	case "generate_schedule":
		task = "Recommend cron schedules for security tasks that would complement the existing schedule shown, avoiding overlap and peak business hours."
	case "optimize_schedule":
		task = "Analyze the current schedules for inefficiency (tasks running more often than needed, redundant overlap) and recommend optimizations."
	case "detect_conflicts":
		task = "Detect scheduling conflicts among the tasks shown (same/overlapping run times, resource contention) and describe each conflict found."
	case "recommend_windows":
		task = "Recommend optimal execution time windows for different task categories (maintenance, security scans, reporting, heavy tasks), based on the current schedule."
	case "explain_purpose":
		task = "Explain what the focus task does and why it's likely scheduled the way it is. If no focus task was given, explain the overall scheduled task setup shown."
	default:
		c.JSON(400, gin.H{"error": "unknown action"})
		return
	}

	prompt := fmt.Sprintf(`You are a SOC automation engineer reviewing this organization's real scheduled task configuration.

%s

Task: %s

Base your answer strictly on the data above — do not invent task names or schedules not present in the data. If there isn't enough data to detect a conflict or issue, say so. Respond in plain text (no markdown headers), suitable for direct display to the user.`, stectx, task)

	resp, err := services.CallLLM(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"response": strings.TrimSpace(resp), "action": b.Action})
}

// POST /api/ste/report
func PostSTEReport(c *gin.Context) {
	tid := tenantIDFromContext(c)
	actor := usernameFromContext(c)
	var b struct {
		ReportType string `json:"report_type"`
	}
	c.ShouldBindJSON(&b)
	steAudit(tid, "", "", "report_generated", actor, fmt.Sprintf("Report type: %s", b.ReportType))
	c.JSON(http.StatusOK, gin.H{
		"ok":          true,
		"report_type": b.ReportType,
		"generated_at": time.Now().Format(time.RFC3339),
		"summary":     fmt.Sprintf("%s report generated successfully. Download will begin shortly.", b.ReportType),
	})
}

func parseIntParam(s string, def int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}
