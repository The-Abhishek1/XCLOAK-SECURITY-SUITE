package repositories

import (
	"database/sql"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func SaveYaraMatches(matches []models.YaraMatch) error {

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

// GetYaraMatches returns the most recent YARA matches across all agents
// (or for a single agent if agentID is non-empty), newest first.
func GetYaraMatches(agentID string) ([]models.YaraMatch, error) {

	var rows *sql.Rows
	var err error

	if agentID != "" {
		rows, err = database.DB.Query(`
			SELECT id, agent_id, file_path, rule_name, severity, description, created_at
			FROM yara_matches
			WHERE agent_id = $1
			ORDER BY id DESC
			LIMIT 200
		`, agentID)
	} else {
		rows, err = database.DB.Query(`
			SELECT id, agent_id, file_path, rule_name, severity, description, created_at
			FROM yara_matches
			ORDER BY id DESC
			LIMIT 200
		`)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matches []models.YaraMatch

	for rows.Next() {
		var m models.YaraMatch
		if err := rows.Scan(&m.ID, &m.AgentID, &m.FilePath, &m.RuleName, &m.Severity, &m.Description, &m.CreatedAt); err == nil {
			matches = append(matches, m)
		}
	}

	return matches, nil
}
