package services

// EDR response depth — memory acquisition, full process snapshots, kill-by-name,
// persistence cleanup, and remediation plans.
//
// Task types added here (all require agent-side support):
//
//   memory_dump        — full RAM dump or per-process dump; agent uploads result
//                        via /api/agents/file with artifact_type=memory_dump
//   process_snapshot   — rich process list: parent, cmdline, user, hashes,
//                        loaded modules, open files, per-process connections
//   kill_process_tree  — kill every process matching a name pattern (not just PID)
//   delete_dropped_file — permanently delete a file path on the agent (no backup)
//   delete_registry_key — remove a Windows registry key (e.g. persistence Run key)
//   delete_scheduled_task — remove a Windows or Linux scheduled task / cron job
//
// Remediation plans group these into an ordered, tracked workflow so operators
// can execute a full IR cleanup in one click rather than dispatching tasks one
// by one. Steps run sequentially; the plan is marked "partial" rather than
// aborting when a step fails.

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// ─────────────────────────────────────────────────────────────────────────────
// Memory dump
// ─────────────────────────────────────────────────────────────────────────────

// DispatchMemoryDump queues a memory_dump task for an agent and returns the
// new task ID. If pid > 0, only that process's memory is captured; pid=0
// requests a full RAM dump (requires elevated agent privileges).
func DispatchMemoryDump(agentID, tenantID, pid int, label string) (int, error) {
	payload, _ := json.Marshal(map[string]any{
		"pid":   pid,
		"label": label,
	})
	task := models.AgentTask{
		AgentID:  agentID,
		TaskType: "memory_dump",
		Payload:  payload,
		Status:   "pending",
	}
	if err := CreateTask(task); err != nil {
		return 0, err
	}

	// Look up the new task ID so the caller can track it.
	var taskID int
	database.DB.QueryRow(`
		SELECT id FROM agent_tasks
		WHERE agent_id=$1 AND task_type='memory_dump'
		ORDER BY created_at DESC LIMIT 1
	`, agentID).Scan(&taskID)

	LogEvent("MEMORY_DUMP_DISPATCHED",
		fmt.Sprintf("agent #%d pid=%d label=%q task=%d", agentID, pid, label, taskID),
		"system")
	return taskID, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Process snapshot
// ─────────────────────────────────────────────────────────────────────────────

// DispatchProcessSnapshot queues a rich process snapshot (parent tree, cmdline,
// hashes, loaded modules, open files, per-process connections). The result is
// stored as a forensic artifact of type "process_snapshot" when the agent posts
// the task result back.
func DispatchProcessSnapshot(agentID, tenantID int, collectionID int) (int, error) {
	payload, _ := json.Marshal(map[string]any{
		"collection_id": collectionID,
		"full_detail":   true, // signal the agent to include modules + open files
	})
	task := models.AgentTask{
		AgentID:  agentID,
		TaskType: "process_snapshot",
		Payload:  payload,
		Status:   "pending",
	}
	if err := CreateTask(task); err != nil {
		return 0, err
	}
	var taskID int
	database.DB.QueryRow(`
		SELECT id FROM agent_tasks
		WHERE agent_id=$1 AND task_type='process_snapshot'
		ORDER BY created_at DESC LIMIT 1
	`, agentID).Scan(&taskID)
	return taskID, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Kill process tree
// ─────────────────────────────────────────────────────────────────────────────

// DispatchKillProcessTree queues a kill_process_tree task that terminates every
// process whose name contains processName (case-insensitive). The agent is
// responsible for finding all matching PIDs and recursively killing child
// processes before the parent.
func DispatchKillProcessTree(agentID, tenantID int, processName, reason string) error {
	payload, _ := json.Marshal(map[string]any{
		"process_name": processName,
		"reason":       reason,
	})
	return repositories.CreateTaskPendingApproval(models.AgentTask{
		AgentID:  agentID,
		TaskType: "kill_process_tree",
		Payload:  payload,
		Status:   "pending_approval",
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistence cleanup
// ─────────────────────────────────────────────────────────────────────────────

// DispatchDeleteRegistryKey queues deletion of a Windows registry key.
// keyPath must be the full path, e.g.
//
//	HKCU\Software\Microsoft\Windows\CurrentVersion\Run\malware
func DispatchDeleteRegistryKey(agentID int, keyPath, reason string) error {
	payload, _ := json.Marshal(map[string]any{
		"key_path": keyPath,
		"reason":   reason,
	})
	return repositories.CreateTaskPendingApproval(models.AgentTask{
		AgentID:  agentID,
		TaskType: "delete_registry_key",
		Payload:  payload,
		Status:   "pending_approval",
	})
}

// DispatchDeleteScheduledTask queues removal of a Windows scheduled task or
// Linux cron job. On Windows, name is the task name in Task Scheduler; on
// Linux it is the crontab entry verbatim or the /etc/cron.d filename.
func DispatchDeleteScheduledTask(agentID int, taskName, reason string) error {
	payload, _ := json.Marshal(map[string]any{
		"task_name": taskName,
		"reason":    reason,
	})
	return repositories.CreateTaskPendingApproval(models.AgentTask{
		AgentID:  agentID,
		TaskType: "delete_scheduled_task",
		Payload:  payload,
		Status:   "pending_approval",
	})
}

// DispatchDeleteDroppedFile queues permanent deletion of a file. Unlike
// quarantine_file (which moves the file to a safe path), this is irreversible.
// Use only when the file is confirmed malicious and has already been hashed.
func DispatchDeleteDroppedFile(agentID int, filePath, sha256, reason string) error {
	payload, _ := json.Marshal(map[string]any{
		"file_path": filePath,
		"sha256":    sha256, // agent verifies hash before deleting to prevent TOCTOU
		"reason":    reason,
	})
	return repositories.CreateTaskPendingApproval(models.AgentTask{
		AgentID:  agentID,
		TaskType: "delete_dropped_file",
		Payload:  payload,
		Status:   "pending_approval",
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Remediation plans
// ─────────────────────────────────────────────────────────────────────────────

// StepRequest is the caller-facing input for one remediation step.
type StepRequest struct {
	ActionType string         `json:"action_type"`
	Payload    map[string]any `json:"payload"`
}

// allowedRemediationActions is the whitelist of action types that may appear in
// a remediation plan. This mirrors (and extends) the alert_response whitelist.
var allowedRemediationActions = map[string]bool{
	"kill_process":           true,
	"kill_process_tree":      true,
	"isolate_host":           true,
	"quarantine_file":        true,
	"delete_dropped_file":    true,
	"delete_registry_key":    true,
	"delete_scheduled_task":  true,
	"memory_dump":            true,
	"process_snapshot":       true,
	"collect_processes":      true,
	"collect_connections":    true,
	"collect_file_hashes":    true,
	"fim_scan":               true,
	"vulnerability_scan":     true,
}

// CreateRemediationPlan stores a plan + its steps. Steps are not dispatched
// until explicitly triggered via ExecuteRemediationPlan or ExecuteStep.
func CreateRemediationPlan(incidentID *int, agentID, tenantID int, label, username string, steps []StepRequest) (int, error) {
	for _, s := range steps {
		if !allowedRemediationActions[s.ActionType] {
			return 0, fmt.Errorf("action_type %q not permitted in remediation plans", s.ActionType)
		}
	}

	var planID int
	err := database.DB.QueryRow(`
		INSERT INTO remediation_plans (incident_id, tenant_id, agent_id, label, created_by, status)
		VALUES ($1,$2,$3,$4,$5,'pending') RETURNING id
	`, incidentID, tenantID, agentID, label, username).Scan(&planID)
	if err != nil {
		return 0, err
	}

	for i, s := range steps {
		payloadJSON, _ := json.Marshal(s.Payload)
		_, err := database.DB.Exec(`
			INSERT INTO remediation_steps (plan_id, step_order, action_type, payload, status)
			VALUES ($1,$2,$3,$4,'pending')
		`, planID, i, s.ActionType, payloadJSON)
		if err != nil {
			log.Printf("[Remediation] insert step %d for plan %d: %v", i, planID, err)
		}
	}

	LogEvent("REMEDIATION_PLAN_CREATED",
		fmt.Sprintf("plan #%d agent #%d steps=%d label=%q by %s", planID, agentID, len(steps), label, username),
		username)
	return planID, nil
}

// GetRemediationPlan loads a plan with all its steps.
func GetRemediationPlan(planID, tenantID int) (*models.RemediationPlan, error) {
	var p models.RemediationPlan
	err := database.DB.QueryRow(`
		SELECT id, incident_id, tenant_id, agent_id, label, created_by, status, created_at, completed_at
		FROM remediation_plans WHERE id=$1 AND tenant_id=$2
	`, planID, tenantID).Scan(
		&p.ID, &p.IncidentID, &p.TenantID, &p.AgentID, &p.Label,
		&p.CreatedBy, &p.Status, &p.CreatedAt, &p.CompletedAt,
	)
	if err != nil {
		return nil, err
	}

	rows, err := database.DB.Query(`
		SELECT id, plan_id, step_order, action_type, payload, status, task_id, result, executed_at, completed_at
		FROM remediation_steps WHERE plan_id=$1 ORDER BY step_order
	`, planID)
	if err != nil {
		return &p, nil
	}
	defer rows.Close()
	for rows.Next() {
		var s models.RemediationStep
		rows.Scan(&s.ID, &s.PlanID, &s.StepOrder, &s.ActionType, &s.Payload,
			&s.Status, &s.TaskID, &s.Result, &s.ExecutedAt, &s.CompletedAt)
		p.Steps = append(p.Steps, s)
	}
	return &p, nil
}

// ListRemediationPlans returns plans for an incident (or all plans for a
// tenant if incidentID is 0), newest first.
func ListRemediationPlans(incidentID, tenantID int) ([]models.RemediationPlan, error) {
	var rows interface {
		Next() bool
		Scan(dest ...any) error
		Close() error
		Err() error
	}
	var err error
	if incidentID > 0 {
		rows, err = database.DB.Query(`
			SELECT id, incident_id, tenant_id, agent_id, label, created_by, status, created_at, completed_at
			FROM remediation_plans
			WHERE tenant_id=$1 AND incident_id=$2
			ORDER BY created_at DESC LIMIT 50
		`, tenantID, incidentID)
	} else {
		rows, err = database.DB.Query(`
			SELECT id, incident_id, tenant_id, agent_id, label, created_by, status, created_at, completed_at
			FROM remediation_plans
			WHERE tenant_id=$1
			ORDER BY created_at DESC LIMIT 50
		`, tenantID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []models.RemediationPlan{}
	for rows.Next() {
		var p models.RemediationPlan
		rows.Scan(&p.ID, &p.IncidentID, &p.TenantID, &p.AgentID, &p.Label,
			&p.CreatedBy, &p.Status, &p.CreatedAt, &p.CompletedAt)
		out = append(out, p)
	}
	return out, nil
}

// ExecuteRemediationPlan dispatches all pending steps in order in a background
// goroutine, waiting for each step's task to complete before starting the next.
func ExecuteRemediationPlan(planID, tenantID int, username string) error {
	plan, err := GetRemediationPlan(planID, tenantID)
	if err != nil {
		return fmt.Errorf("plan not found")
	}
	if plan.Status == "running" {
		return fmt.Errorf("plan already running")
	}
	if plan.Status == "completed" {
		return fmt.Errorf("plan already completed")
	}

	database.DB.Exec(`UPDATE remediation_plans SET status='running' WHERE id=$1`, planID)
	LogEvent("REMEDIATION_PLAN_STARTED",
		fmt.Sprintf("plan #%d by %s", planID, username), username)

	go runRemediationPlan(plan)
	return nil
}

func runRemediationPlan(plan *models.RemediationPlan) {
	failed := false
	for i := range plan.Steps {
		s := &plan.Steps[i]
		if s.Status != "pending" {
			continue
		}

		taskID, stepErr := dispatchRemediationStep(plan.AgentID, s)
		now := time.Now()
		s.ExecutedAt = &now

		if stepErr != nil {
			failed = true
			database.DB.Exec(`
				UPDATE remediation_steps SET status='failed', result=$1, executed_at=NOW()
				WHERE id=$2
			`, stepErr.Error(), s.ID)
			log.Printf("[Remediation] plan #%d step #%d failed: %v", plan.ID, s.ID, stepErr)
			continue
		}

		database.DB.Exec(`
			UPDATE remediation_steps SET status='dispatched', task_id=$1, executed_at=NOW()
			WHERE id=$2
		`, taskID, s.ID)

		// Poll for task completion (up to 5 minutes per step).
		completed := waitForTask(taskID, 5*time.Minute)
		completedAt := time.Now()
		if completed {
			database.DB.Exec(`
				UPDATE remediation_steps SET status='completed', completed_at=$1
				WHERE id=$2
			`, completedAt, s.ID)
		} else {
			failed = true
			database.DB.Exec(`
				UPDATE remediation_steps SET status='failed', result='timed out waiting for agent', completed_at=$1
				WHERE id=$2
			`, completedAt, s.ID)
		}
	}

	finalStatus := "completed"
	if failed {
		finalStatus = "partial"
	}
	// Check if any step is still pending (was skipped due to earlier failure).
	var pendingCount int
	database.DB.QueryRow(`SELECT COUNT(*) FROM remediation_steps WHERE plan_id=$1 AND status='pending'`, plan.ID).Scan(&pendingCount)
	if pendingCount > 0 {
		finalStatus = "partial"
	}

	database.DB.Exec(`
		UPDATE remediation_plans SET status=$1, completed_at=NOW() WHERE id=$2
	`, finalStatus, plan.ID)
	log.Printf("[Remediation] plan #%d finished: %s", plan.ID, finalStatus)
}

// ExecuteStep dispatches a single pending step immediately (for manual step-by-step
// execution without running the full plan sequence).
func ExecuteStep(planID, stepID, tenantID int, username string) error {
	var s models.RemediationStep
	var agentID int
	err := database.DB.QueryRow(`
		SELECT rs.id, rs.plan_id, rs.step_order, rs.action_type, rs.payload, rs.status,
		       rp.agent_id
		FROM remediation_steps rs
		JOIN remediation_plans rp ON rp.id = rs.plan_id
		WHERE rs.id=$1 AND rs.plan_id=$2 AND rp.tenant_id=$3
	`, stepID, planID, tenantID).Scan(
		&s.ID, &s.PlanID, &s.StepOrder, &s.ActionType, &s.Payload, &s.Status, &agentID,
	)
	if err != nil {
		return fmt.Errorf("step not found")
	}
	if s.Status != "pending" && s.Status != "failed" {
		return fmt.Errorf("step is not in a dispatchable state (%s)", s.Status)
	}

	taskID, dispErr := dispatchRemediationStep(agentID, &s)
	if dispErr != nil {
		database.DB.Exec(`UPDATE remediation_steps SET status='failed', result=$1 WHERE id=$2`,
			dispErr.Error(), stepID)
		return dispErr
	}
	database.DB.Exec(`
		UPDATE remediation_steps SET status='dispatched', task_id=$1, executed_at=NOW()
		WHERE id=$2
	`, taskID, stepID)
	LogEvent("REMEDIATION_STEP_DISPATCHED",
		fmt.Sprintf("plan #%d step #%d (%s) task #%d by %s", planID, stepID, s.ActionType, taskID, username),
		username)
	return nil
}

// dispatchRemediationStep translates a step into an AgentTask and either queues
// it for approval (destructive) or dispatches it immediately.
func dispatchRemediationStep(agentID int, s *models.RemediationStep) (int, error) {
	task := models.AgentTask{
		AgentID:  agentID,
		TaskType: s.ActionType,
		Payload:  s.Payload,
	}

	var err error
	if IsDestructiveTask(s.ActionType) {
		err = repositories.CreateTaskPendingApproval(task)
	} else {
		err = repositories.CreateTask(task)
	}
	if err != nil {
		return 0, err
	}

	var taskID int
	database.DB.QueryRow(`
		SELECT id FROM agent_tasks WHERE agent_id=$1 AND task_type=$2
		ORDER BY created_at DESC LIMIT 1
	`, agentID, s.ActionType).Scan(&taskID)
	return taskID, nil
}

// waitForTask polls until the task reaches a terminal state or the deadline.
func waitForTask(taskID int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(10 * time.Second)
		var status string
		database.DB.QueryRow(`SELECT status FROM agent_tasks WHERE id=$1`, taskID).Scan(&status)
		if status == "completed" {
			return true
		}
		if status == "failed" || status == "expired" {
			return false
		}
	}
	return false
}

// SyncRemediationStepStatus is called from the task-completion webhook to keep
// the step record in sync with the underlying agent task result.
func SyncRemediationStepStatus(taskID int, status, result string) {
	if status != "completed" && status != "failed" {
		return
	}
	stepStatus := status
	database.DB.Exec(`
		UPDATE remediation_steps
		SET status=$1, result=$2, completed_at=NOW()
		WHERE task_id=$3 AND status='dispatched'
	`, stepStatus, result, taskID)
}
