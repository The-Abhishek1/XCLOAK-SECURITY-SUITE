package services

import (
	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

func CreateTask(task models.AgentTask) error {

	err := repositories.CreateTask(task)

	if err != nil {
		return err
	}

	LogEvent(
		"CREATE_TASK",
		task.TaskType,
		"admin",
	)
	go PublishTaskDispatched(task)

	return nil
}

// GetPendingTasks returns an agent's pending tasks and immediately marks
// each as "running". repositories.GetPendingTasks only ever selects
// status='pending'; without flipping it here, a task whose execution takes
// longer than the agent's poll interval (any recursive scan — e.g. a
// fleet-wide YARA sweep, or fim_scan over a large tree) stays 'pending'
// until the goroutine running it finally submits a result, so the next
// poll fetches and re-dispatches the same task concurrently. Confirmed
// live: a YARA scan_yara task against /bin,/usr/bin,etc took longer than
// the 15s poll interval and was executed twice, submitting duplicate
// results — repositories.MarkTaskRunning already existed for exactly this
// but was never called anywhere.
func GetPendingTasks(
	agentID string,
) ([]models.AgentTask, error) {

	tasks, err := repositories.GetPendingTasks(
		agentID,
	)
	if err != nil {
		return nil, err
	}

	for _, t := range tasks {
		_ = repositories.MarkTaskRunning(t.ID)
	}

	return tasks, nil
}

func CompleteTask(
	taskID int,
	result string,
	agentID int,
) error {

	var taskType string
	database.DB.QueryRow(`SELECT task_type FROM agent_tasks WHERE id=$1`, taskID).Scan(&taskType)

	if err := repositories.CompleteTask(taskID, result, agentID); err != nil {
		return err
	}

	go PublishTaskCompleted(taskID, agentID, taskType, result)
	return nil
}
