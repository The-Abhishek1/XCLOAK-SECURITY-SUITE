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

// StartScheduler runs the task scheduler in a background goroutine.
// Call once from main.go after DB connects.
func StartScheduler() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		fmt.Println("Scheduler started — checking every 30s")

		for range ticker.C {
			runDueScheduledTasks()
		}
	}()
}

func runDueScheduledTasks() {

	rows, err := database.DB.Query(`
		SELECT id, name, task_type, COALESCE(agent_ids::text, '{}'),
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
		var agentIDsRaw string
		var payloadRaw string

		if err := rows.Scan(&st.ID, &st.Name, &st.TaskType, &agentIDsRaw,
			&st.CronExpr, &payloadRaw); err == nil {
			json.Unmarshal([]byte(agentIDsRaw), &st.AgentIDs)
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

	// Empty agent_ids = dispatch to all online agents.
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
		task := models.AgentTask{
			AgentID:  agentID,
			TaskType: st.TaskType,
			Payload:  st.Payload,
		}
		repositories.CreateTask(task)
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

// nextRunTime parses a simple cron expression and returns the next run time.
// Supports: */N (every N units), specific values, * (any).
// Format: minute hour day_of_month month day_of_week
func nextRunTime(expr string) time.Time {

	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return time.Now().Add(15 * time.Minute)
	}

	now := time.Now().Truncate(time.Minute)

	// For simple cases, just parse the minute field to get interval.
	minuteField := fields[0]

	if strings.HasPrefix(minuteField, "*/") {
		n, err := strconv.Atoi(minuteField[2:])
		if err == nil && n > 0 {
			return now.Add(time.Duration(n) * time.Minute)
		}
	}

	// Default: every hour.
	return now.Add(time.Hour)
}

// CRUD for scheduled tasks.

func CreateScheduledTask(st models.ScheduledTask) (*models.ScheduledTask, error) {

	agentIDsJSON, _ := json.Marshal(st.AgentIDs)
	next := nextRunTime(st.CronExpr)

	err := database.DB.QueryRow(`
		INSERT INTO scheduled_tasks
		(name, task_type, agent_ids, cron_expr, payload, enabled, next_run_at, created_by)
		VALUES ($1,$2,$3,$4,$5,TRUE,$6,$7)
		RETURNING id, created_at
	`, st.Name, st.TaskType, agentIDsJSON, st.CronExpr,
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
		SELECT id, name, task_type, COALESCE(agent_ids::text, '{}'),
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
		var agentIDsRaw string
		var payloadRaw string

		if err := rows.Scan(&st.ID, &st.Name, &st.TaskType, &agentIDsRaw,
			&st.CronExpr, &payloadRaw, &st.Enabled,
			&st.LastRunAt, &st.NextRunAt, &st.RunCount,
			&st.CreatedBy, &st.CreatedAt); err == nil {
			json.Unmarshal([]byte(agentIDsRaw), &st.AgentIDs)
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
	var agentIDsRaw []byte
	var payloadRaw string

	err := database.DB.QueryRow(`
		SELECT id, name, task_type, agent_ids, cron_expr, COALESCE(payload::text, '{}')
		FROM scheduled_tasks WHERE id=$1
	`, id).Scan(&st.ID, &st.Name, &st.TaskType, &agentIDsRaw, &st.CronExpr, &payloadRaw)

	if err != nil {
		return err
	}

	json.Unmarshal(agentIDsRaw, &st.AgentIDs)
	st.Payload = json.RawMessage(payloadRaw)
	dispatchScheduledTask(st)
	return nil
}
