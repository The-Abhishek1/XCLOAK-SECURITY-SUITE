package services

import (
	"fmt"
	"time"

	"xcloak-ngfw/database"
)

const (
	// Tasks older than this that are still pending get expired.
	// Destructive tasks have a shorter window.
	defaultTaskTTL     = 1 * time.Hour
	destructiveTaskTTL = 15 * time.Minute
)

// destructiveTasks are tasks that must not run stale — if the agent was
// offline for too long, executing these could cause damage on a now-resolved
// incident.
var destructiveTasks = []string{
	"kill_process",
	"isolate_host",
	"quarantine_file",
	"apply_firewall_rules",
	"execute_script",
}

// IsDestructiveTask reports whether a task type is in destructiveTasks —
// used by the playbook engine (and the manual alert-response endpoint) to
// decide which actions need human approval before dispatch, regardless of
// whether they were triggered autonomously or by a one-click manual action.
func IsDestructiveTask(taskType string) bool {
	for _, t := range destructiveTasks {
		if t == taskType {
			return true
		}
	}
	return false
}

// ExpireStaleTasks marks old pending tasks as 'expired' so agents don't
// execute them when they come back online after a long outage.
// Call from the scheduler every 5 minutes.
func ExpireStaleTasks() {
	// Expire unapproved destructive actions after the same destructive TTL —
	// an unreviewed isolate_host/kill_process request from a since-resolved
	// or false-positive alert shouldn't sit in the approval queue forever.
	res, err := database.DB.Exec(fmt.Sprintf(`
		UPDATE agent_tasks
		SET status = 'expired',
		    result = 'Task expired: not approved within %d minutes'
		WHERE status = 'pending_approval'
		  AND created_at < NOW() - INTERVAL '%d minutes'
	`, int(destructiveTaskTTL.Minutes()), int(destructiveTaskTTL.Minutes())))

	if err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			fmt.Printf("[TaskExpiry] Expired %d unapproved destructive task(s)\n", n)
		}
	}

	// Expire destructive tasks after 15 minutes. Covers 'running' as well as
	// 'pending' — GetPendingTasks now flips a fetched task to 'running'
	// immediately (see task_service.go), so a task whose agent died or lost
	// connectivity mid-execution would otherwise sit in 'running' forever,
	// since this query used to be the only thing that ever moved a task out
	// of a non-terminal status.
	destructiveList := "'" + joinStrings(destructiveTasks, "','") + "'"
	res, err = database.DB.Exec(fmt.Sprintf(`
		UPDATE agent_tasks
		SET status = 'expired',
		    result = 'Task expired: agent was offline too long for this destructive action'
		WHERE status IN ('pending', 'running')
		  AND task_type IN (%s)
		  AND created_at < NOW() - INTERVAL '%d minutes'
	`, destructiveList, int(destructiveTaskTTL.Minutes())))

	if err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			fmt.Printf("[TaskExpiry] Expired %d stale destructive task(s)\n", n)
		}
	}

	// Expire all other tasks after 1 hour — same 'running' reasoning as above.
	res, err = database.DB.Exec(fmt.Sprintf(`
		UPDATE agent_tasks
		SET status = 'expired',
		    result = 'Task expired: agent did not pick up within %d minutes'
		WHERE status IN ('pending', 'running')
		  AND task_type NOT IN (%s)
		  AND created_at < NOW() - INTERVAL '%d minutes'
	`, int(defaultTaskTTL.Minutes()), destructiveList, int(defaultTaskTTL.Minutes())))

	if err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			fmt.Printf("[TaskExpiry] Expired %d stale standard task(s)\n", n)
		}
	}
}

func joinStrings(ss []string, sep string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}

// GetTaskExpiryStats returns a count of expired tasks for monitoring.
func GetTaskExpiryStats() (total int, lastHour int) {
	database.DB.QueryRow(`SELECT COUNT(*) FROM agent_tasks WHERE status='expired'`).Scan(&total)
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM agent_tasks
		WHERE status='expired' AND created_at > NOW() - INTERVAL '1 hour'
	`).Scan(&lastHour)
	return
}
