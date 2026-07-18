package repositories

import (
	"errors"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// ErrYaraRuleNotFound is returned by tenant-scoped mutations below when no
// row matches id+tenantID — covers both a nonexistent id and a real id
// belonging to another tenant.
var ErrYaraRuleNotFound = errors.New("yara rule not found")

func CreateYaraRule(rule models.YaraRule, tenantID int) error {

	_, err := database.DB.Exec(`
		INSERT INTO yara_rules
		(name, description, rule_content, enabled, tenant_id)
		VALUES ($1,$2,$3,$4,$5)
	`,
		rule.Name,
		rule.Description,
		rule.RuleContent,
		rule.Enabled,
		tenantID,
	)

	return err
}

// GetYaraRules returns rules belonging to tenantID only. Use this from
// user-facing API paths that have a real tenant context from the request.
func GetYaraRules(tenantID int) ([]models.YaraRule, error) {
	return queryYaraRules(`
		SELECT id, name, description, rule_content, enabled, tenant_id, created_at
		FROM yara_rules
		WHERE tenant_id = $1
		ORDER BY id
	`, tenantID)
}

// GetEnabledYaraRules returns enabled rules for tenantID — this is what the
// agent fetches before running a scan, scoped so a tenant's agent only
// scans against that tenant's own detection content.
func GetEnabledYaraRules(tenantID int) ([]models.YaraRule, error) {
	return queryYaraRules(`
		SELECT id, name, description, rule_content, enabled, tenant_id, created_at
		FROM yara_rules
		WHERE enabled = true AND tenant_id = $1
		ORDER BY id
	`, tenantID)
}

func queryYaraRules(query string, args ...interface{}) ([]models.YaraRule, error) {

	rows, err := database.DB.Query(query, args...)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := []models.YaraRule{}

	for rows.Next() {
		var r models.YaraRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.RuleContent, &r.Enabled, &r.TenantID, &r.CreatedAt); err == nil {
			rules = append(rules, r)
		}
	}

	return rules, nil
}

func UpdateYaraRule(id string, rule models.YaraRule, tenantID int) error {

	tag, err := database.DB.Exec(`
		UPDATE yara_rules
		SET name = $1, description = $2, rule_content = $3, enabled = $4
		WHERE id = $5 AND tenant_id = $6
	`,
		rule.Name,
		rule.Description,
		rule.RuleContent,
		rule.Enabled,
		id,
		tenantID,
	)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrYaraRuleNotFound
	}
	return nil
}

func DeleteYaraRule(id string, tenantID int) error {

	tag, err := database.DB.Exec(`DELETE FROM yara_rules WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrYaraRuleNotFound
	}
	return nil
}

func SetYaraRuleEnabled(id string, enabled bool, tenantID int) error {

	tag, err := database.DB.Exec(`
		UPDATE yara_rules SET enabled = $1 WHERE id = $2 AND tenant_id = $3
	`, enabled, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrYaraRuleNotFound
	}
	return nil
}
