package services

import (
	"fmt"
	"strings"

	"xcloak-ngfw/models"
)

func DetectThreats(
	log models.Log,
) {

	message := strings.ToLower(
		log.LogMessage,
	)

	if strings.Contains(
		message,
		"failed password",
	) {

		alert := models.Alert{
			AgentID:  log.AgentID,
			Severity: "high",
			RuleName: "Failed Password",
			Fingerprint: fmt.Sprintf(
				"%d-failed-password",
				log.AgentID,
			),
			LogMessage: log.LogMessage,
		}

		MapMITRE(&alert)

		CreateAlert(alert)
		CorrelateAlert(alert)
	}

	if strings.Contains(
		message,
		"accepted password",
	) {

		alert := models.Alert{
			AgentID:  log.AgentID,
			Severity: "low",
			RuleName: "Successful Login",
			Fingerprint: fmt.Sprintf(
				"%d-success-login",
				log.AgentID,
			),
			LogMessage: log.LogMessage,
		}

		MapMITRE(&alert)

		CreateAlert(alert)
		CorrelateAlert(alert)
	}

	if strings.Contains(
		message,
		"sudo:",
	) {

		alert := models.Alert{
			AgentID:  log.AgentID,
			Severity: "medium",
			RuleName: "Sudo Usage",
			Fingerprint: fmt.Sprintf(
				"%d-sudo",
				log.AgentID,
			),
			LogMessage: log.LogMessage,
		}

		MapMITRE(&alert)

		CreateAlert(alert)
		CorrelateAlert(alert)
	}

	if strings.Contains(
		message,
		"useradd",
	) {

		alert := models.Alert{
			AgentID:  log.AgentID,
			Severity: "high",
			RuleName: "New User Created",
			Fingerprint: fmt.Sprintf(
				"%d-useradd",
				log.AgentID,
			),
			LogMessage: log.LogMessage,
		}

		MapMITRE(&alert)

		CreateAlert(alert)
		CorrelateAlert(alert)
	}
}
