package repositories

import (
	"encoding/json"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func CreateSigmaRule(
	rule models.SigmaRule,
) error {

	keywordsJSON, _ := json.Marshal(
		rule.Keywords,
	)

	_, err := database.DB.Exec(`
		INSERT INTO sigma_rules
		(
			title,
			severity,
			mitre_tactic,
			mitre_technique,
			mitre_name,
			keywords,
			enabled
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
	`,
		rule.Title,
		rule.Severity,
		rule.MitreTactic,
		rule.MitreTechnique,
		rule.MitreName,
		keywordsJSON,
		rule.Enabled,
	)

	return err
}

func GetRules() (
	[]models.SigmaRule,
	error,
) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			title,
			severity,
			mitre_tactic,
			mitre_technique,
			mitre_name,
			keywords,
			enabled,
			created_at
		FROM sigma_rules
		ORDER BY id
	`)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var rules []models.SigmaRule

	for rows.Next() {

		var rule models.SigmaRule

		var keywords []byte

		err := rows.Scan(
			&rule.ID,
			&rule.Title,
			&rule.Severity,
			&rule.MitreTactic,
			&rule.MitreTechnique,
			&rule.MitreName,
			&keywords,
			&rule.Enabled,
			&rule.CreatedAt,
		)

		if err != nil {
			continue
		}

		json.Unmarshal(
			keywords,
			&rule.Keywords,
		)

		rules = append(
			rules,
			rule,
		)
	}

	return rules, nil
}

func GetSigmaRuleByID(
	id string,
) (*models.SigmaRule, error) {

	var rule models.SigmaRule

	var keywords []byte

	err := database.DB.QueryRow(`
		SELECT
			id,
			title,
			severity,
			mitre_tactic,
			mitre_technique,
			mitre_name,
			keywords,
			enabled,
			created_at
		FROM sigma_rules
		WHERE id = $1
	`,
		id,
	).Scan(
		&rule.ID,
		&rule.Title,
		&rule.Severity,
		&rule.MitreTactic,
		&rule.MitreTechnique,
		&rule.MitreName,
		&keywords,
		&rule.Enabled,
		&rule.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	json.Unmarshal(
		keywords,
		&rule.Keywords,
	)

	return &rule, nil
}

func UpdateSigmaRule(
	id string,
	rule models.SigmaRule,
) error {

	keywordsJSON, _ := json.Marshal(
		rule.Keywords,
	)

	_, err := database.DB.Exec(`
		UPDATE sigma_rules
		SET
			title = $1,
			severity = $2,
			mitre_tactic = $3,
			mitre_technique = $4,
			mitre_name = $5,
			keywords = $6,
			enabled = $7
		WHERE id = $8
	`,
		rule.Title,
		rule.Severity,
		rule.MitreTactic,
		rule.MitreTechnique,
		rule.MitreName,
		keywordsJSON,
		rule.Enabled,
		id,
	)

	return err
}

func DeleteSigmaRule(
	id string,
) error {

	_, err := database.DB.Exec(`
		DELETE FROM sigma_rules
		WHERE id = $1
	`,
		id,
	)

	return err
}

func EnableRule(
	id string,
) error {

	_, err := database.DB.Exec(`
		UPDATE sigma_rules
		SET enabled = true
		WHERE id = $1
	`,
		id,
	)

	return err
}

func DisableRule(
	id string,
) error {

	_, err := database.DB.Exec(`
		UPDATE sigma_rules
		SET enabled = false
		WHERE id = $1
	`,
		id,
	)

	return err
}

func GetEnabledRules() (
	[]models.SigmaRule,
	error,
) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			title,
			severity,
			mitre_tactic,
			mitre_technique,
			mitre_name,
			keywords,
			enabled,
			created_at
		FROM sigma_rules
		WHERE enabled = true
	`)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var rules []models.SigmaRule

	for rows.Next() {

		var rule models.SigmaRule
		var keywords []byte

		err := rows.Scan(
			&rule.ID,
			&rule.Title,
			&rule.Severity,
			&rule.MitreTactic,
			&rule.MitreTechnique,
			&rule.MitreName,
			&keywords,
			&rule.Enabled,
			&rule.CreatedAt,
		)

		if err != nil {
			continue
		}

		json.Unmarshal(
			keywords,
			&rule.Keywords,
		)

		rules = append(
			rules,
			rule,
		)
	}

	return rules, nil
}
