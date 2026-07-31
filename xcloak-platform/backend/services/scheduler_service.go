package services

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

func StartScheduler() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		slog.Info("scheduler: started, checking every 30s")
		for range ticker.C {
			WithSingletonLock("scheduler", func() {
				runDueScheduledTasks()
				ExpireStaleTasks()
				ExpireStaleApprovals()
				RunDueScriptSchedules()
				RunDueSTETasks()
				SyncAllRunningSTEExecutions()
				RunDueRPESchedules()
			})
		}
	}()
	// Run retention clean-up once at start, then nightly.
	go func() {
		ApplyRetentionPolicies()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			ApplyRetentionPolicies()
		}
	}()
	// Ensure the next-month endpoint_logs partition exists.
	// CREATE FUNCTION is idempotent so daily cadence is safe.
	go func() {
		EnsureNextMonthPartition()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			EnsureNextMonthPartition()
		}
	}()

	StartBehavioralScorer()
	StartProcessNoveltyDetector()
}

// ExpireStaleApprovals marks any still-pending aq_requests row whose due_at
// has passed as 'expired' — the status/count already exists on the
// dashboard and analytics endpoints, but nothing was ever setting it.
func ExpireStaleApprovals() {
	database.DB.Exec(`UPDATE aq_requests SET status='expired', updated_at=NOW() WHERE status='pending' AND due_at IS NOT NULL AND due_at < NOW()`)
}

// DispatchScriptExecution resolves target to a real agent by hostname and
// dispatches a real execute_script AgentTask carrying the script's actual
// content. Returns the execution's initial status ("running" if dispatched,
// "failed" if no matching agent or script content was found), the created
// agent_tasks.id (0 if none), and a failure reason (empty on success). Lives
// in services (not api, where PostSRExecute/PostSRApprove call it from) so
// the scheduler ticker below — which runs in this package and can't import
// api without an import cycle — can dispatch scheduled scripts through the
// exact same code path rather than a second, divergent copy of it.
func DispatchScriptExecution(tid int, scriptID, target, runAs, params string) (status string, agentTaskID int, failReason string) {
	var content, language string
	err := database.DB.QueryRow(`SELECT content,language FROM sr_scripts WHERE script_id=$1 AND tenant_id=$2`, scriptID, tid).Scan(&content, &language)
	if err != nil || content == "" {
		return "failed", 0, "script not found in library or has no content"
	}

	var agentID int
	err = database.DB.QueryRow(
		`SELECT id FROM agents WHERE tenant_id=$1 AND (hostname=$2 OR ip_address=$2)`, tid, target,
	).Scan(&agentID)
	if err != nil {
		return "failed", 0, fmt.Sprintf("no registered agent matches target %q", target)
	}

	shell := "bash"
	switch language {
	case "python", "python3":
		shell = "python3"
	case "powershell", "pwsh":
		shell = "pwsh"
	case "sh":
		shell = "sh"
	}
	payload, _ := json.Marshal(map[string]string{"script": content, "shell": shell, "label": scriptID, "run_as": runAs, "parameters": params})

	task := models.AgentTask{AgentID: agentID, TaskType: "execute_script", Payload: payload}
	if err := repositories.CreateTask(task); err != nil {
		return "failed", 0, "failed to dispatch task: " + err.Error()
	}
	database.DB.QueryRow(
		`SELECT id FROM agent_tasks WHERE agent_id=$1 AND task_type='execute_script' ORDER BY id DESC LIMIT 1`, agentID,
	).Scan(&agentTaskID)
	return "running", agentTaskID, ""
}

func srScheduleAudit(tid int, scriptID, scriptName, action, actor, details string) {
	database.DB.Exec(
		`INSERT INTO sr_audit (tenant_id,action,script_id,script_name,actor,details) VALUES ($1,$2,$3,$4,$5,$6)`,
		tid, action, scriptID, scriptName, actor, details,
	)
}

// RunDueScriptSchedules dispatches sr_schedules whose next_run has passed,
// through the same DispatchScriptExecution path PostSRExecute uses for a
// manual run, then advances last_run/next_run so each schedule actually
// recurs instead of firing once at creation and going stale forever.
// "once" disables itself after its single run; "cron" reuses this file's
// own NextRunTime parser (minimal */N-minute support, +1h fallback) rather
// than pulling in a cron library this repo doesn't otherwise depend on —
// an honest, documented limitation, not a fabricated full cron engine.
// "event"-type schedules are never picked up here at all: PostSRSchedule
// leaves their next_run NULL since they have no time basis, and this
// query's own WHERE clause skips NULL next_run rows.
func RunDueScriptSchedules() {
	rows, err := database.DB.Query(`
		SELECT id, tenant_id, script_id, script_name, schedule_type, cron_expr, target, run_as, COALESCE(parameters,'{}')
		FROM sr_schedules
		WHERE enabled=1 AND next_run IS NOT NULL AND next_run <= NOW()`)
	if err != nil {
		return
	}
	type dueSchedule struct {
		id, tenantID                                           int
		scriptID, scriptName, schedType, target, runAs, params string
		cronExpr                                               *string
	}
	due := []dueSchedule{}
	for rows.Next() {
		var d dueSchedule
		if rows.Scan(&d.id, &d.tenantID, &d.scriptID, &d.scriptName, &d.schedType, &d.cronExpr, &d.target, &d.runAs, &d.params) == nil {
			due = append(due, d)
		}
	}
	rows.Close()

	for _, d := range due {
		status, agentTaskID, failReason := DispatchScriptExecution(d.tenantID, d.scriptID, d.target, d.runAs, d.params)
		execID := fmt.Sprintf("EXEC-%04d-%d", d.tenantID, time.Now().UnixMilli()%1000000)
		var agentTaskArg interface{}
		if agentTaskID != 0 {
			agentTaskArg = agentTaskID
		}
		database.DB.Exec(
			`INSERT INTO sr_executions (tenant_id,execution_id,script_id,script_name,target,target_count,status,agent_task_id,stderr,trigger_source,run_as,parameters,executed_by) VALUES ($1,$2,$3,$4,$5,1,$6,$7,$8,'scheduled',$9,$10,'scheduler')`,
			d.tenantID, execID, d.scriptID, d.scriptName, d.target, status, agentTaskArg, failReason, d.runAs, d.params,
		)
		srScheduleAudit(d.tenantID, d.scriptID, d.scriptName, "executed", "scheduler", fmt.Sprintf("Scheduled execution %s dispatched: target=%s status=%s", execID, d.target, status))

		if d.schedType == "once" {
			database.DB.Exec(`UPDATE sr_schedules SET last_run=NOW(), next_run=NULL, enabled=0 WHERE id=$1`, d.id)
			continue
		}
		var next time.Time
		switch d.schedType {
		case "hourly":
			next = time.Now().UTC().Add(time.Hour)
		case "daily":
			next = time.Now().UTC().AddDate(0, 0, 1)
		case "weekly":
			next = time.Now().UTC().AddDate(0, 0, 7)
		case "monthly":
			next = time.Now().UTC().AddDate(0, 1, 0)
		case "cron":
			expr := ""
			if d.cronExpr != nil {
				expr = *d.cronExpr
			}
			next = NextRunTime(expr)
		default:
			next = time.Now().UTC().Add(time.Hour)
		}
		database.DB.Exec(`UPDATE sr_schedules SET last_run=NOW(), next_run=$1 WHERE id=$2`, next, d.id)
	}
}

// scanAgentIDs converts PostgreSQL integer[] text "{1,2}" or JSON "[1,2]" to []int
func scanAgentIDs(raw string) []int {
	if raw == "" || raw == "{}" || raw == "[]" || raw == "null" {
		return nil
	}
	// PostgreSQL array format: {1,2,3}
	if strings.HasPrefix(raw, "{") {
		raw = "[" + raw[1:len(raw)-1] + "]"
	}
	ids := []int{}
	json.Unmarshal([]byte(raw), &ids)
	return ids
}

func runDueScheduledTasks() {
	rows, err := database.DB.Query(`
		SELECT id, name, task_type,
		       COALESCE(array_to_json(agent_ids)::text, '[]'),
		       cron_expr, COALESCE(payload::text, '{}'), tenant_id
		FROM scheduled_tasks
		WHERE enabled = TRUE
		AND (next_run_at IS NULL OR next_run_at <= now())
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	due := []models.ScheduledTask{}
	for rows.Next() {
		var st models.ScheduledTask
		var agentIDsRaw, payloadRaw string
		if err := rows.Scan(&st.ID, &st.Name, &st.TaskType, &agentIDsRaw,
			&st.CronExpr, &payloadRaw, &st.TenantID); err == nil {
			st.AgentIDs = scanAgentIDs(agentIDsRaw)
			st.Payload = json.RawMessage(payloadRaw)
			due = append(due, st)
		}
	}
	rows.Close()
	for _, st := range due {
		dispatchScheduledTask(st)
	}
}

// dispatchScheduledTask fans a task out to its target agents, always
// constrained to st.TenantID — both the "no explicit agent_ids" fallback
// (every online agent) and an explicit agent_ids list are filtered to that
// tenant's own agents, so one tenant's schedule can never dispatch
// (including destructive task types) against another tenant's fleet.
func dispatchScheduledTask(st models.ScheduledTask) {
	targets := []int{}
	if len(st.AgentIDs) == 0 {
		agents, err := repositories.GetAgents(st.TenantID)
		if err == nil {
			for _, a := range agents {
				if a.Status == "online" {
					targets = append(targets, a.ID)
				}
			}
		}
	} else {
		targets = filterAgentIDsByTenant(st.AgentIDs, st.TenantID)
	}
	for _, agentID := range targets {
		repositories.CreateTask(models.AgentTask{
			AgentID:  agentID,
			TaskType: st.TaskType,
			Payload:  st.Payload,
		})
	}
	next := NextRunTime(st.CronExpr)
	database.DB.Exec(`
		UPDATE scheduled_tasks
		SET last_run_at = now(), next_run_at = $1, run_count = run_count + 1
		WHERE id = $2
	`, next, st.ID)
	slog.Info("scheduler: dispatched task", "task", st.Name, "agents", len(targets), "next", next.Format("15:04:05"))
}

// filterAgentIDsByTenant returns only the ids that actually belong to
// tenantID, dropping any explicitly-listed agent id from another tenant.
func filterAgentIDsByTenant(ids []int, tenantID int) []int {
	if len(ids) == 0 {
		return nil
	}
	rows, err := database.DB.Query(
		`SELECT id FROM agents WHERE id = ANY($1) AND tenant_id = $2`, ids, tenantID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	valid := []int{}
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			valid = append(valid, id)
		}
	}
	return valid
}

// NextRunTime returns its result in UTC. next_run_at/next_run columns in
// this codebase are plain TIMESTAMP (no time zone), and on a server whose
// OS-level local time isn't UTC, a naive time.Now() writes local wall-clock
// digits verbatim into that column — which then compares as if it *were*
// UTC against Postgres's own NOW() (session tz is UTC here), skewing every
// due-schedule comparison by the server's UTC offset. Confirmed live: a
// schedule seeded 2 minutes in the past on this IST (+5:30) dev box read
// back as ~5.5 hours in the *future* and never fired.
func NextRunTime(expr string) time.Time {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return time.Now().UTC().Add(15 * time.Minute)
	}
	now := time.Now().UTC().Truncate(time.Minute)
	minuteField := fields[0]
	if strings.HasPrefix(minuteField, "*/") {
		n, err := strconv.Atoi(minuteField[2:])
		if err == nil && n > 0 {
			return now.Add(time.Duration(n) * time.Minute)
		}
	}
	return now.Add(time.Hour)
}

func CreateScheduledTask(st models.ScheduledTask, tenantID int) (*models.ScheduledTask, error) {
	// Reject any explicitly-listed agent id that doesn't belong to the
	// creating tenant up front, rather than silently dropping it later at
	// dispatch time.
	if len(st.AgentIDs) > 0 {
		valid := filterAgentIDsByTenant(st.AgentIDs, tenantID)
		if len(valid) != len(st.AgentIDs) {
			return nil, fmt.Errorf("one or more agent_ids do not belong to your tenant")
		}
	}

	// Convert []int to PostgreSQL integer[] literal: {1,2,3}
	pgArray := "{}"
	if len(st.AgentIDs) > 0 {
		parts := make([]string, len(st.AgentIDs))
		for i, id := range st.AgentIDs {
			parts[i] = strconv.Itoa(id)
		}
		pgArray = "{" + strings.Join(parts, ",") + "}"
	}
	next := NextRunTime(st.CronExpr)
	err := database.DB.QueryRow(`
		INSERT INTO scheduled_tasks
		(name, task_type, agent_ids, cron_expr, payload, enabled, next_run_at, created_by, tenant_id)
		VALUES ($1,$2,$3::integer[],$4,$5,TRUE,$6,$7,$8)
		RETURNING id, created_at
	`, st.Name, st.TaskType, pgArray, st.CronExpr,
		st.Payload, next, st.CreatedBy, tenantID).
		Scan(&st.ID, &st.CreatedAt)
	if err != nil {
		return nil, err
	}
	st.NextRunAt = &next
	return &st, nil
}

func GetScheduledTasks(tenantID int) ([]models.ScheduledTask, error) {
	rows, err := database.DB.Query(`
		SELECT id, name, task_type,
		       COALESCE(array_to_json(agent_ids)::text, '[]'),
		       cron_expr, COALESCE(payload::text, '{}'),
		       enabled, last_run_at, next_run_at, run_count, created_by, created_at
		FROM scheduled_tasks WHERE tenant_id=$1 ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tasks := []models.ScheduledTask{}
	for rows.Next() {
		var st models.ScheduledTask
		var agentIDsRaw, payloadRaw string
		if err := rows.Scan(&st.ID, &st.Name, &st.TaskType, &agentIDsRaw,
			&st.CronExpr, &payloadRaw, &st.Enabled,
			&st.LastRunAt, &st.NextRunAt, &st.RunCount,
			&st.CreatedBy, &st.CreatedAt); err == nil {
			st.AgentIDs = scanAgentIDs(agentIDsRaw)
			st.Payload = json.RawMessage(payloadRaw)
			tasks = append(tasks, st)
		}
	}
	return tasks, nil
}

func ToggleScheduledTask(id string, enabled bool, tenantID int) error {
	tag, err := database.DB.Exec(
		`UPDATE scheduled_tasks SET enabled=$1 WHERE id=$2 AND tenant_id=$3`, enabled, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return fmt.Errorf("scheduled task not found")
	}
	return nil
}

func DeleteScheduledTask(id string, tenantID int) error {
	tag, err := database.DB.Exec(`DELETE FROM scheduled_tasks WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return fmt.Errorf("scheduled task not found")
	}
	return nil
}

func RunScheduledTaskNow(id string, tenantID int) error {
	var st models.ScheduledTask
	var agentIDsRaw, payloadRaw string

	err := database.DB.QueryRow(`
		SELECT id, name, task_type,
		       COALESCE(array_to_json(agent_ids)::text, '[]'),
		       cron_expr, COALESCE(payload::text, '{}')
		FROM scheduled_tasks WHERE id=$1 AND tenant_id=$2
	`, id, tenantID).Scan(&st.ID, &st.Name, &st.TaskType, &agentIDsRaw, &st.CronExpr, &payloadRaw)
	if err != nil {
		return err
	}
	st.AgentIDs = scanAgentIDs(agentIDsRaw)
	st.Payload = json.RawMessage(payloadRaw)
	st.TenantID = tenantID
	dispatchScheduledTask(st)
	return nil
}
