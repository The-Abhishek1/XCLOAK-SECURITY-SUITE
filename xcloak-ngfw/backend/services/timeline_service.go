package services

import (
	"sort"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func GetAgentTimeline(
	agentID int,
) ([]models.TimelineEvent, error) {

	var timeline []models.TimelineEvent

	alerts, _ := repositories.GetAlertsByAgentID(
		agentID,
	)

	for _, alert := range alerts {

		if alert.AgentID != agentID {
			continue
		}

		timeline = append(
			timeline,
			models.TimelineEvent{
				EventType: "alert",
				Message:   alert.RuleName,
				CreatedAt: alert.CreatedAt,
			},
		)
	}

	incidents, _ := repositories.GetIncidentsByAgentID(
		agentID,
	)

	for _, incident := range incidents {

		if incident.AgentID != agentID {
			continue
		}

		timeline = append(
			timeline,
			models.TimelineEvent{
				EventType: "incident",
				Message:   incident.Title,
				CreatedAt: incident.CreatedAt,
			},
		)
	}

	executions, _ := repositories.GetPlaybookExecutionsByAgentID(
		agentID,
	)

	for _, execution := range executions {

		if execution.AgentID != agentID {
			continue
		}

		timeline = append(
			timeline,
			models.TimelineEvent{
				EventType: "playbook",
				Message:   execution.ActionType,
				CreatedAt: execution.CreatedAt,
			},
		)
	}

	sort.Slice(
		timeline,
		func(i, j int) bool {

			return timeline[i].CreatedAt.Before(
				timeline[j].CreatedAt,
			)
		},
	)

	return timeline, nil
}
