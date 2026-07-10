package services

import (
	"fmt"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

func SaveYaraMatches(
	matches []models.YaraMatch,
) error {

	err := repositories.SaveYaraMatches(
		matches,
	)

	if err != nil {
		return err
	}

	for _, match := range matches {

		logMessage := fmt.Sprintf("%s matched on %s", match.RuleName, match.FilePath)
		if match.FileHash != "" {
			logMessage += fmt.Sprintf(" (sha256 %s)", match.FileHash)
		}
		if match.Description != "" {
			logMessage += ": " + match.Description
		}

		alert := models.Alert{
			AgentID: match.AgentID,

			Severity: match.Severity,

			RuleName: "YARA Match",

			LogMessage: logMessage,

			MitreTactic: "Execution",

			MitreTechnique: "T1059",

			MitreName: "Command and Scripting Interpreter",

			Fingerprint: match.RuleName +
				"-" +
				match.FilePath,
		}

		// CreateAlert already fires CorrelateAlert itself (in a goroutine,
		// see alert_service.go) — a second explicit call here used to
		// double-run every correlation rule for every single YARA match
		// (double-counting event_count rules, double-attempting incident
		// creation).
		CreateAlert(alert)
		go PublishYARAMatch(match.AgentID, match.RuleName, match.FilePath)
	}

	return nil
}
