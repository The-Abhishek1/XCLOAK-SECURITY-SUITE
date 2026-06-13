package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func CreateYaraRule(rule models.YaraRule) error {

	_, err := database.DB.Exec(`
		INSERT INTO yara_rules
		(name, description, rule_content, enabled)
		VALUES ($1,$2,$3,$4)
	`,
		rule.Name,
		rule.Description,
		rule.RuleContent,
		rule.Enabled,
	)

	return err
}

func GetYaraRules() ([]models.YaraRule, error) {

	rows, err := database.DB.Query(`
		SELECT id, name, description, rule_content, enabled, created_at
		FROM yara_rules
		ORDER BY id
	`)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []models.YaraRule

	for rows.Next() {
		var r models.YaraRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.RuleContent, &r.Enabled, &r.CreatedAt); err == nil {
			rules = append(rules, r)
		}
	}

	return rules, nil
}

// GetEnabledYaraRules returns all enabled rules — this is what the agent
// fetches before running a scan.
func GetEnabledYaraRules() ([]models.YaraRule, error) {

	rows, err := database.DB.Query(`
		SELECT id, name, description, rule_content, enabled, created_at
		FROM yara_rules
		WHERE enabled = true
		ORDER BY id
	`)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []models.YaraRule

	for rows.Next() {
		var r models.YaraRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.RuleContent, &r.Enabled, &r.CreatedAt); err == nil {
			rules = append(rules, r)
		}
	}

	return rules, nil
}

func UpdateYaraRule(id string, rule models.YaraRule) error {

	_, err := database.DB.Exec(`
		UPDATE yara_rules
		SET name = $1, description = $2, rule_content = $3, enabled = $4
		WHERE id = $5
	`,
		rule.Name,
		rule.Description,
		rule.RuleContent,
		rule.Enabled,
		id,
	)

	return err
}

func DeleteYaraRule(id string) error {

	_, err := database.DB.Exec(`DELETE FROM yara_rules WHERE id = $1`, id)
	return err
}

func SetYaraRuleEnabled(id string, enabled bool) error {

	_, err := database.DB.Exec(`
		UPDATE yara_rules SET enabled = $1 WHERE id = $2
	`, enabled, id)

	return err
}
