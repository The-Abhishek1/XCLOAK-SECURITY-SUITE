package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func SaveYaraMatches(
	matches []models.YaraMatch,
) error {

	for _, match := range matches {

		_, err := database.DB.Exec(`
			INSERT INTO yara_matches
			(
				agent_id,
				file_path,
				rule_name,
				severity,
				description
			)
			VALUES ($1,$2,$3,$4,$5)
		`,
			match.AgentID,
			match.FilePath,
			match.RuleName,
			match.Severity,
			match.Description,
		)

		if err != nil {
			return err
		}
	}

	return nil
}
