package repositories

import (
	"encoding/json"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func CreateSigmaRule(rule models.SigmaRule) error {

	keywordsJSON, _ := json.Marshal(rule.Keywords)
	selectionsJSON, _ := json.Marshal(rule.Selections)

	_, err := database.DB.Exec(`
		INSERT INTO sigma_rules
		(
			title,
			severity,
			mitre_tactic,
			mitre_technique,
			mitre_name,
			keywords,
			selections,
			condition,
			enabled
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`,
		rule.Title,
		rule.Severity,
		rule.MitreTactic,
		rule.MitreTechnique,
		rule.MitreName,
		keywordsJSON,
		selectionsJSON,
		rule.Condition,
		rule.Enabled,
	)

	return err
}

func scanSigmaRule(row interface {
	Scan(dest ...interface{}) error
}) (*models.SigmaRule, error) {

	var rule models.SigmaRule
	var keywords, selections []byte

	err := row.Scan(
		&rule.ID,
		&rule.Title,
		&rule.Severity,
		&rule.MitreTactic,
		&rule.MitreTechnique,
		&rule.MitreName,
		&keywords,
		&selections,
		&rule.Condition,
		&rule.Enabled,
		&rule.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	json.Unmarshal(keywords, &rule.Keywords)
	json.Unmarshal(selections, &rule.Selections)

	return &rule, nil
}

const sigmaSelectCols = `
	id,
	title,
	severity,
	mitre_tactic,
	mitre_technique,
	mitre_name,
	keywords,
	COALESCE(selections, '{}'::jsonb),
	COALESCE(condition, ''),
	enabled,
	created_at
`

func GetRules() ([]models.SigmaRule, error) {

	rows, err := database.DB.Query(`
		SELECT ` + sigmaSelectCols + `
		FROM sigma_rules
		ORDER BY id
	`)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []models.SigmaRule

	for rows.Next() {
		rule, err := scanSigmaRule(rows)
		if err != nil {
			continue
		}
		rules = append(rules, *rule)
	}

	return rules, nil
}

func GetSigmaRuleByID(id string) (*models.SigmaRule, error) {

	row := database.DB.QueryRow(`
		SELECT `+sigmaSelectCols+`
		FROM sigma_rules
		WHERE id = $1
	`, id)

	return scanSigmaRule(row)
}

func UpdateSigmaRule(id string, rule models.SigmaRule) error {

	keywordsJSON, _ := json.Marshal(rule.Keywords)
	selectionsJSON, _ := json.Marshal(rule.Selections)

	_, err := database.DB.Exec(`
		UPDATE sigma_rules
		SET
			title = $1,
			severity = $2,
			mitre_tactic = $3,
			mitre_technique = $4,
			mitre_name = $5,
			keywords = $6,
			selections = $7,
			condition = $8,
			enabled = $9
		WHERE id = $10
	`,
		rule.Title,
		rule.Severity,
		rule.MitreTactic,
		rule.MitreTechnique,
		rule.MitreName,
		keywordsJSON,
		selectionsJSON,
		rule.Condition,
		rule.Enabled,
		id,
	)

	return err
}

func DeleteSigmaRule(id string) error {

	_, err := database.DB.Exec(`
		DELETE FROM sigma_rules
		WHERE id = $1
	`, id)

	return err
}

func EnableRule(id string) error {

	_, err := database.DB.Exec(`
		UPDATE sigma_rules
		SET enabled = true
		WHERE id = $1
	`, id)

	return err
}

func DisableRule(id string) error {

	_, err := database.DB.Exec(`
		UPDATE sigma_rules
		SET enabled = false
		WHERE id = $1
	`, id)

	return err
}

func GetEnabledRules() ([]models.SigmaRule, error) {

	rows, err := database.DB.Query(`
		SELECT ` + sigmaSelectCols + `
		FROM sigma_rules
		WHERE enabled = true
	`)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []models.SigmaRule

	for rows.Next() {
		rule, err := scanSigmaRule(rows)
		if err != nil {
			continue
		}
		rules = append(rules, *rule)
	}

	return rules, nil
}
