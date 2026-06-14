package services

import "xcloak-ngfw/models"

// CreateTaskForAgent is a convenience wrapper used internally (e.g. from the
// live logs WS handler) to dispatch a task without going through the API layer.
func CreateTaskForAgent(agentID int, taskType string) {
	_ = CreateTask(models.AgentTask{
		AgentID:  agentID,
		TaskType: taskType,
	})
}
