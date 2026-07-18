package repositories

import (
	"database/sql"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// SaveYaraMatches inserts matches with tenant_id resolved from the owning
// agent rather than a client-supplied value — same pattern as CreateAlert.
func SaveYaraMatches(matches []models.YaraMatch) error {

	for _, match := range matches {

		_, err := database.DB.Exec(`
			INSERT INTO yara_matches
			(
				agent_id,
				file_path,
				rule_name,
				severity,
				description,
				matched_strings,
				file_hash,
				tenant_id
			)
			VALUES ($1,$2,$3,$4,$5,$6,$7, (SELECT tenant_id FROM agents WHERE id = $1))
		`,
			match.AgentID,
			match.FilePath,
			match.RuleName,
			match.Severity,
			match.Description,
			match.MatchedStrings,
			match.FileHash,
		)

		if err != nil {
			return err
		}
	}

	return nil
}

// GetYaraMatches returns the most recent YARA matches for tenantID (or for a
// single agent within that tenant if agentID is non-empty), newest first.
func GetYaraMatches(agentID string, tenantID int) ([]models.YaraMatch, error) {

	var rows *sql.Rows
	var err error

	if agentID != "" {
		rows, err = database.DB.Query(`
			SELECT id, agent_id, file_path, rule_name, severity, description, matched_strings, file_hash, tenant_id, created_at
			FROM yara_matches
			WHERE agent_id = $1 AND tenant_id = $2
			ORDER BY id DESC
			LIMIT 200
		`, agentID, tenantID)
	} else {
		rows, err = database.DB.Query(`
			SELECT id, agent_id, file_path, rule_name, severity, description, matched_strings, file_hash, tenant_id, created_at
			FROM yara_matches
			WHERE tenant_id = $1
			ORDER BY id DESC
			LIMIT 200
		`, tenantID)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	matches := []models.YaraMatch{}

	for rows.Next() {
		var m models.YaraMatch
		if err := rows.Scan(&m.ID, &m.AgentID, &m.FilePath, &m.RuleName, &m.Severity, &m.Description,
			&m.MatchedStrings, &m.FileHash, &m.TenantID, &m.CreatedAt); err == nil {
			matches = append(matches, m)
		}
	}

	return matches, nil
}
