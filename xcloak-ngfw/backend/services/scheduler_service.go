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
			runDueScheduledTasks()
			ExpireStaleTasks()
		}
	}()
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
		       cron_expr, COALESCE(payload::text, '{}')
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
			&st.CronExpr, &payloadRaw); err == nil {
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

func dispatchScheduledTask(st models.ScheduledTask) {
	targets := st.AgentIDs
	if len(targets) == 0 {
		agents, err := repositories.GetAgents()
		if err == nil {
			for _, a := range agents {
				if a.Status == "online" {
					targets = append(targets, a.ID)
				}
			}
		}
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

func CreateScheduledTask(st models.ScheduledTask) (*models.ScheduledTask, error) {
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
		(name, task_type, agent_ids, cron_expr, payload, enabled, next_run_at, created_by)
		VALUES ($1,$2,$3::integer[],$4,$5,TRUE,$6,$7)
		RETURNING id, created_at
	`, st.Name, st.TaskType, pgArray, st.CronExpr,
		st.Payload, next, st.CreatedBy).
		Scan(&st.ID, &st.CreatedAt)
	if err != nil {
		return nil, err
	}
	st.NextRunAt = &next
	return &st, nil
}

func GetScheduledTasks() ([]models.ScheduledTask, error) {
	rows, err := database.DB.Query(`
		SELECT id, name, task_type,
		       COALESCE(array_to_json(agent_ids)::text, '[]'),
		       cron_expr, COALESCE(payload::text, '{}'),
		       enabled, last_run_at, next_run_at, run_count, created_by, created_at
		FROM scheduled_tasks ORDER BY created_at DESC
	`)
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

func ToggleScheduledTask(id string, enabled bool) error {
	_, err := database.DB.Exec(
		`UPDATE scheduled_tasks SET enabled=$1 WHERE id=$2`, enabled, id)
	return err
}

func DeleteScheduledTask(id string) error {
	_, err := database.DB.Exec(`DELETE FROM scheduled_tasks WHERE id=$1`, id)
	return err
}

func RunScheduledTaskNow(id string) error {
	var st models.ScheduledTask
	var agentIDsRaw, payloadRaw string

	err := database.DB.QueryRow(`
		SELECT id, name, task_type,
		       COALESCE(array_to_json(agent_ids)::text, '[]'),
		       cron_expr, COALESCE(payload::text, '{}')
		FROM scheduled_tasks WHERE id=$1
	`, id).Scan(&st.ID, &st.Name, &st.TaskType, &agentIDsRaw, &st.CronExpr, &payloadRaw)
	if err != nil {
		return err
	}
	st.AgentIDs = scanAgentIDs(agentIDsRaw)
	st.Payload = json.RawMessage(payloadRaw)
	dispatchScheduledTask(st)
	return nil
}
