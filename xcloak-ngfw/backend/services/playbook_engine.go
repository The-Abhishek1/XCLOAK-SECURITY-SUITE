package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func ExecutePlaybooks(
	alert models.Alert,
) {

	println(
		"SOAR Trigger:",
		alert.RuleName,
	)

	playbooks, err := repositories.GetEnabledPlaybooks()

	if err != nil {
		return
	}

	for _, playbook := range playbooks {

		println(
			"Checking playbook:",
			playbook.Name,
		)

		if playbook.TriggerType != alert.RuleName {

			println(
				"Skipped",
			)

			continue
		}

		println(
			"MATCHED PLAYBOOK",
		)

		actions, err := repositories.GetPlaybookActions(
			playbook.ID,
		)

		if err != nil {

			println(
				"Failed to load actions",
			)

			continue
		}

		for _, action := range actions {

			println(
				"Executing Action:",
				action.ActionType,
			)

			err := CreateTask(
				models.AgentTask{
					AgentID:  alert.AgentID,
					TaskType: action.ActionType,
					Payload:  action.Payload,
				},
			)

			status := "success"

			if err != nil {
				status = "failed"
			}

			LogPlaybookExecution(
				models.PlaybookExecution{
					PlaybookID: playbook.ID,

					AgentID: alert.AgentID,

					AlertRule: alert.RuleName,

					ActionType: action.ActionType,

					Status: status,
				},
			)
		}
	}
}
