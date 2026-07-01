package services

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func StartScheduler() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		fmt.Println("Scheduler started — checking every 30s")
		for range ticker.C {
			WithSingletonLock("scheduler", func() {
				runDueScheduledTasks()
				ExpireStaleTasks()
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
	StartBehavioralScorer()
	StartProcessNoveltyDetector()
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
	var ids []int
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

	var due []models.ScheduledTask
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
	var targets []int
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
	next := nextRunTime(st.CronExpr)
	database.DB.Exec(`
		UPDATE scheduled_tasks
		SET last_run_at = now(), next_run_at = $1, run_count = run_count + 1
		WHERE id = $2
	`, next, st.ID)
	fmt.Printf("Scheduler: dispatched '%s' to %d agents, next at %s\n",
		st.Name, len(targets), next.Format("15:04:05"))
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
	var valid []int
	for rows.Next() {
		var id int
		if rows.Scan(&id) == nil {
			valid = append(valid, id)
		}
	}
	return valid
}

func nextRunTime(expr string) time.Time {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return time.Now().Add(15 * time.Minute)
	}
	now := time.Now().Truncate(time.Minute)
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
	next := nextRunTime(st.CronExpr)
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

	var tasks []models.ScheduledTask
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
