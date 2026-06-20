package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
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

	return nil
}

func GetPendingTasks(
	agentID string,
) ([]models.AgentTask, error) {

	return repositories.GetPendingTasks(
		agentID,
	)
}

func CompleteTask(
	taskID int,
	result string,
	agentID int,
) error {

	return repositories.CompleteTask(
		taskID,
		result,
		agentID,
	)
}
