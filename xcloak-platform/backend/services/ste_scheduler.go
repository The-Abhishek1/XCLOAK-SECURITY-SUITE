package services

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// steRealAgentTaskTypes are the exact task_type strings the agent's own
// executor understands (xcloak-agent-desktop/agent/executor.go's switch
// cases). api/scheduled_tasks_enterprise.go's ste_tasks.task_type comes from
// a much broader picklist (report generation, webhooks, script-language
// names with no script-content field anywhere to send, cleanup jobs with no
// agent-side implementation, etc.) that used to be dispatched to a random
// agent verbatim regardless of whether the agent had any idea what to do
// with it. DispatchSTETask below fails honestly for anything not in this
// list instead of fabricating a dispatch that would silently no-op (or
// error) on the agent side.
var steRealAgentTaskTypes = map[string]bool{
	"collect_processes": true, "collect_connections": true, "collect_services": true,
	"collect_packages": true, "collect_users": true, "collect_auth_logs": true,
	"kill_process": true, "collect_file": true, "isolate_host": true,
	"quarantine_file": true, "execute_script": true, "collect_file_hashes": true,
	"scan_yara": true, "fim_scan": true, "vulnerability_scan": true,
	"apply_firewall_rules": true, "restore_file": true, "collect_cron_jobs": true,
	"collect_kernel_modules": true, "collect_suid_binaries": true, "collect_disk_usage": true,
}

// ResolveSTETargetAgents resolves a task's target_type/target_ids to real
// agent IDs registered for the tenant. Never invents a target — returns an
// empty slice if nothing matches, so the caller can fail honestly instead of
// fabricating a dispatched execution.
func ResolveSTETargetAgents(tid int, targetType, targetIDs string) []int {
	agentIDs := []int{}
	switch targetType {
	case "all", "":
		rows, err := database.DB.Query(`SELECT id FROM agents WHERE tenant_id=$1`, tid)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var id int
				if rows.Scan(&id) == nil {
					agentIDs = append(agentIDs, id)
				}
			}
		}
	default:
		var hostnames []string
		if json.Unmarshal([]byte(targetIDs), &hostnames) == nil {
			for _, h := range hostnames {
				var id int
				if database.DB.QueryRow(`SELECT id FROM agents WHERE tenant_id=$1 AND (hostname=$2 OR ip_address=$2)`, tid, h).Scan(&id) == nil {
					agentIDs = append(agentIDs, id)
				}
			}
		}
	}
	return agentIDs
}

// DispatchSTETask resolves the task's real targets and dispatches a real
// agent_tasks row to each — but only for task types the agent executor
// actually implements (see steRealAgentTaskTypes); anything else fails
// honestly rather than sending the agent a task type it has no case for.
// Destructive task types go through the same pending_approval gate as every
// other dispatcher in this codebase. Lives in services (not api, where the
// manual "Run Now" handler calls it from) so the scheduler ticker — which
// can't import api without a cycle — dispatches through the same code a
// manual run uses, rather than a second, divergent copy.
func DispatchSTETask(tid int, taskType, scheduleConfig, targetType, targetIDs string) (status string, agentTaskIDs []int, failReason string) {
	if !steRealAgentTaskTypes[taskType] {
		return "failed", nil, fmt.Sprintf("task_type %q has no execution backend in this build", taskType)
	}
	agentIDs := ResolveSTETargetAgents(tid, targetType, targetIDs)
	if len(agentIDs) == 0 {
		return "failed", nil, "no registered agent matches this task's target configuration"
	}
	payload := json.RawMessage(scheduleConfig)
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	destructive := IsDestructiveTask(taskType)
	for _, agentID := range agentIDs {
		task := models.AgentTask{AgentID: agentID, TaskType: taskType, Payload: payload}
		var err error
		if destructive {
			err = repositories.CreateTaskPendingApproval(task)
		} else {
			err = repositories.CreateTask(task)
		}
		if err != nil {
			continue
		}
		var atID int
		database.DB.QueryRow(`SELECT id FROM agent_tasks WHERE agent_id=$1 AND task_type=$2 ORDER BY id DESC LIMIT 1`, agentID, taskType).Scan(&atID)
		if atID != 0 {
			agentTaskIDs = append(agentTaskIDs, atID)
		}
	}
	if len(agentTaskIDs) == 0 {
		return "failed", nil, "failed to dispatch task to any resolved agent"
	}
	if destructive {
		return "pending_agent_approval", agentTaskIDs, ""
	}
	return "running", agentTaskIDs, ""
}

func steTaskAudit(tid int, taskID, taskName, action, actor, details string) {
	database.DB.Exec(`INSERT INTO ste_audit (tenant_id,task_id,task_name,action,actor,details) VALUES ($1,$2,$3,$4,$5,$6)`,
		tid, taskID, taskName, action, actor, details)
}

func steTaskNotify(tid int, taskID, taskName, eventType, message, severity string) {
	database.DB.Exec(`INSERT INTO ste_notifications (tenant_id,task_id,task_name,event_type,message,severity) VALUES ($1,$2,$3,$4,$5,$6)`,
		tid, taskID, taskName, eventType, message, severity)
}

// ExecuteSTETaskNow dispatches a real execution for a task (bypassing the
// ste_approvals workflow, since the caller already confirmed approval was
// either not required or has just been granted). Used by the manual-run
// endpoint, the approval-decision path, and the scheduler tick below, so an
// approved or due task actually runs instead of just flipping a status flag.
func ExecuteSTETaskNow(tid int, dbID, taskID, name, trigger, actor string) (execID string, status string, err error) {
	var taskType, scheduleConfig, targetType, targetIDs string
	err = database.DB.QueryRow(`SELECT task_type,schedule_config,target_type,target_ids FROM ste_tasks WHERE tenant_id=$1 AND id=$2`, tid, dbID).
		Scan(&taskType, &scheduleConfig, &targetType, &targetIDs)
	if err != nil {
		return "", "", fmt.Errorf("task not found")
	}

	dispatchStatus, agentTaskIDs, failReason := DispatchSTETask(tid, taskType, scheduleConfig, targetType, targetIDs)
	agentTaskIDsJSON, _ := json.Marshal(agentTaskIDs)

	execID = fmt.Sprintf("EX-%08d", time.Now().UnixNano()%99999999)
	var eid int
	execStatus := dispatchStatus
	if execStatus == "pending_agent_approval" {
		execStatus = "running"
	}
	dbErr := database.DB.QueryRow(`INSERT INTO ste_executions
		(tenant_id,execution_id,task_id,task_name,status,trigger,executed_by,target_count,error_message,agent_task_ids)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
		tid, execID, taskID, name, execStatus, trigger, actor, len(agentTaskIDs), failReason, string(agentTaskIDsJSON)).Scan(&eid)
	if dbErr != nil {
		return "", "", dbErr
	}

	database.DB.Exec(`UPDATE ste_tasks SET run_count=run_count+1, last_run_at=NOW(), updated_at=NOW() WHERE tenant_id=$1 AND id=$2`, tid, dbID)
	steTaskAudit(tid, taskID, name, "executed", actor, fmt.Sprintf("trigger=%s targets=%d", trigger, len(agentTaskIDs)))

	if dispatchStatus == "failed" {
		database.DB.Exec(`UPDATE ste_executions SET status='failed',end_time=NOW() WHERE id=$1`, eid)
		database.DB.Exec(`UPDATE ste_tasks SET failure_count=failure_count+1 WHERE id=$1`, dbID)
		steTaskNotify(tid, taskID, name, "task_failed", fmt.Sprintf("Task '%s' failed to dispatch: %s", name, failReason), "critical")
		return execID, "failed", nil
	}

	steTaskNotify(tid, taskID, name, "task_started", fmt.Sprintf("Task '%s' dispatched to %d agent(s) by %s", name, len(agentTaskIDs), actor), "info")
	return execID, "running", nil
}

// SyncSTEExecutions reflects the real status of every agent_tasks row a
// still-"running" execution is waiting on. An execution only turns
// "completed" once ALL of its dispatched tasks genuinely completed; it
// turns "failed" as soon as any of them fails or expires. Never fabricates
// completion via a timer. Exported (moved from api/scheduled_tasks_enterprise.go)
// so both the read-triggered call from GetSTEExecutions and the periodic
// background sweep below share one implementation.
func SyncSTEExecutions(tid int, ids []int) {
	if len(ids) == 0 {
		return
	}
	rows, err := database.DB.Query(`SELECT id,execution_id,task_id,task_name,agent_task_ids,start_time FROM ste_executions WHERE tenant_id=$1 AND status='running' AND id = ANY($2)`,
		tid, pqIntArrayLiteral(ids))
	if err != nil || rows == nil {
		return
	}
	type pending struct {
		id                       int
		execID, taskID, taskName string
		agentTaskIDs             []int
		startTime                time.Time
	}
	list := []pending{}
	for rows.Next() {
		var p pending
		var atJSON string
		if rows.Scan(&p.id, &p.execID, &p.taskID, &p.taskName, &atJSON, &p.startTime) == nil {
			json.Unmarshal([]byte(atJSON), &p.agentTaskIDs)
			list = append(list, p)
		}
	}
	rows.Close()

	for _, p := range list {
		if len(p.agentTaskIDs) == 0 {
			continue
		}
		allDone, anyFailed := true, false
		for _, atID := range p.agentTaskIDs {
			var st string
			database.DB.QueryRow(`SELECT status FROM agent_tasks WHERE id=$1`, atID).Scan(&st)
			if st != "completed" && st != "failed" && st != "expired" && st != "rejected" {
				allDone = false
			}
			if st == "failed" || st == "expired" || st == "rejected" {
				anyFailed = true
			}
		}
		if !allDone {
			continue
		}
		finalStatus := "completed"
		if anyFailed {
			finalStatus = "failed"
		}
		dur := int(time.Since(p.startTime).Milliseconds())
		exitCode := 0
		if anyFailed {
			exitCode = 1
		}
		database.DB.Exec(`UPDATE ste_executions SET status=$1,end_time=NOW(),duration=$2,exit_code=$3 WHERE id=$4 AND status='running'`,
			finalStatus, dur, exitCode, p.id)
		if finalStatus == "completed" {
			database.DB.Exec(`UPDATE ste_tasks SET success_count=success_count+1 WHERE tenant_id=$1 AND task_id=$2`, tid, p.taskID)
			steTaskNotify(tid, p.taskID, p.taskName, "task_completed", fmt.Sprintf("Task '%s' completed successfully", p.taskName), "info")
		} else {
			database.DB.Exec(`UPDATE ste_tasks SET failure_count=failure_count+1 WHERE tenant_id=$1 AND task_id=$2`, tid, p.taskID)
			steTaskNotify(tid, p.taskID, p.taskName, "task_failed", fmt.Sprintf("Task '%s' failed", p.taskName), "critical")
		}
	}
}

// SyncAllRunningSTEExecutions is the scheduler-tick variant of
// SyncSTEExecutions — it doesn't require a caller to already know which
// tenant/ids to check, so a dispatched task's completion gets reflected
// even when nobody is actively viewing the Execution History tab. Before
// this existed, syncSTEExecutions (its api-package predecessor) had zero
// callers anywhere in the codebase — every "running" execution stayed
// "running" forever regardless of real agent completion.
func SyncAllRunningSTEExecutions() {
	rows, err := database.DB.Query(`SELECT DISTINCT tenant_id FROM ste_executions WHERE status='running'`)
	if err != nil {
		return
	}
	tenantIDs := []int{}
	for rows.Next() {
		var t int
		if rows.Scan(&t) == nil {
			tenantIDs = append(tenantIDs, t)
		}
	}
	rows.Close()
	for _, tid := range tenantIDs {
		idRows, err := database.DB.Query(`SELECT id FROM ste_executions WHERE tenant_id=$1 AND status='running'`, tid)
		if err != nil {
			continue
		}
		ids := []int{}
		for idRows.Next() {
			var id int
			if idRows.Scan(&id) == nil {
				ids = append(ids, id)
			}
		}
		idRows.Close()
		SyncSTEExecutions(tid, ids)
	}
}

// NextSTERunTime computes the next_run_at for a schedule_type/cron_expr —
// shared by PostSTETask (initial value at creation) and RunDueSTETasks
// (recurrence after each dispatch). Returns nil for schedule types with no
// time basis (event_based has no trigger infrastructure in this repo;
// maintenance_window has no window-aware scheduling infrastructure either)
// rather than fabricating a fixed time that doesn't reflect either concept.
func NextSTERunTime(scheduleType, cronExpr string) *time.Time {
	now := time.Now().UTC()
	var t time.Time
	switch scheduleType {
	case "one_time":
		t = now.Add(time.Hour)
	case "hourly":
		t = now.Add(time.Hour)
	case "daily":
		t = now.AddDate(0, 0, 1)
	case "weekly":
		t = now.AddDate(0, 0, 7)
	case "monthly":
		t = now.AddDate(0, 1, 0)
	case "yearly":
		t = now.AddDate(1, 0, 0)
	case "cron":
		t = NextRunTime(cronExpr)
	default:
		// event_based, maintenance_window: no time basis in this build.
		return nil
	}
	return &t
}

// RunDueSTETasks dispatches ste_tasks whose next_run_at has passed, through
// the same ExecuteSTETaskNow path the manual "Run Now" button uses, then
// advances last_run_at/next_run_at so each schedule actually recurs.
// one_time disables itself after its single run.
func RunDueSTETasks() {
	rows, err := database.DB.Query(`
		SELECT id, tenant_id, task_id, name, schedule_type, cron_expr
		FROM ste_tasks
		WHERE enabled=TRUE AND next_run_at IS NOT NULL AND next_run_at <= NOW()`)
	if err != nil {
		return
	}
	type dueTask struct {
		id, tenantID            int
		taskID, name, schedType string
		cronExpr                *string
	}
	due := []dueTask{}
	for rows.Next() {
		var d dueTask
		if rows.Scan(&d.id, &d.tenantID, &d.taskID, &d.name, &d.schedType, &d.cronExpr) == nil {
			due = append(due, d)
		}
	}
	rows.Close()

	for _, d := range due {
		ExecuteSTETaskNow(d.tenantID, strconv.Itoa(d.id), d.taskID, d.name, "scheduled", "scheduler")

		if d.schedType == "one_time" {
			database.DB.Exec(`UPDATE ste_tasks SET next_run_at=NULL, enabled=FALSE WHERE id=$1`, d.id)
			continue
		}
		cron := ""
		if d.cronExpr != nil {
			cron = *d.cronExpr
		}
		next := NextSTERunTime(d.schedType, cron)
		database.DB.Exec(`UPDATE ste_tasks SET next_run_at=$1 WHERE id=$2`, next, d.id)
	}
}

// pqIntArrayLiteral formats a Go int slice as a Postgres integer array
// literal for use with = ANY($n) — avoids pulling in lib/pq's pq.Array.
func pqIntArrayLiteral(ids []int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(id)
	}
	return "{" + strings.Join(parts, ",") + "}"
}
