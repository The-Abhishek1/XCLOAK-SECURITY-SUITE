package services

import (
	"fmt"

	"xcloak-ngfw/models"
)

func CorrelateAlert(
	alert models.Alert,
) {

	if alert.RuleName != "Sudo Usage" {
		return
	}

	incidentID, err := CreateIncident(
		models.Incident{
			AgentID:     alert.AgentID,
			Title:       "Possible Privilege Escalation",
			Severity:    "critical",
			Description: alert.LogMessage,
			Fingerprint: fmt.Sprintf(
				"%d-privilege-escalation",
				alert.AgentID,
			),
		},
	)

	if err != nil {
		fmt.Println(
			"Incident error:",
			err,
		)
		return
	}

	err = CreateIncidentEvent(
		models.IncidentEvent{
			IncidentID: incidentID,
			EventType:  alert.RuleName,
			Details:    alert.LogMessage,
		},
	)

	if err != nil {
		fmt.Println(
			"Incident event error:",
			err,
		)
	}
}
