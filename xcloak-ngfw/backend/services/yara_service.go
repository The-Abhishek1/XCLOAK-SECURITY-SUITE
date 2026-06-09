package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
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

		alert := models.Alert{
			AgentID: match.AgentID,

			Severity: match.Severity,

			RuleName: "YARA Match",

			LogMessage: match.FilePath,

			MitreTactic: "Execution",

			MitreTechnique: "T1059",

			MitreName: "Command and Scripting Interpreter",

			Fingerprint: match.RuleName +
				"-" +
				match.FilePath,
		}

		CreateAlert(alert)

		CorrelateAlert(alert)
	}

	return nil
}
