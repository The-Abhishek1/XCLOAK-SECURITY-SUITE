package repositories

import (
	"encoding/json"
	"errors"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// ErrSigmaRuleNotFound is returned by tenant-scoped mutations below when no
// row matches id+tenantID — covers both a nonexistent id and a real id
// belonging to another tenant.
var ErrSigmaRuleNotFound = errors.New("sigma rule not found")

func CreateSigmaRule(rule models.SigmaRule, tenantID int) error {

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
			enabled,
			tenant_id
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
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
		tenantID,
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
		&rule.TenantID,
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
	tenant_id,
	created_at
`

// GetRules returns rules belonging to tenantID only. Use this from
// user-facing API paths that have a real tenant context from the request.
func GetRules(tenantID int) ([]models.SigmaRule, error) {

	rows, err := database.DB.Query(`
		SELECT `+sigmaSelectCols+`
		FROM sigma_rules
		WHERE tenant_id = $1
		ORDER BY id
	`, tenantID)

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

// GetSigmaRuleByID fetches a single rule, scoped to tenantID — a request
// for another tenant's rule gets the same "not found" as a nonexistent one.
func GetSigmaRuleByID(id string, tenantID int) (*models.SigmaRule, error) {

	row := database.DB.QueryRow(`
		SELECT `+sigmaSelectCols+`
		FROM sigma_rules
		WHERE id = $1 AND tenant_id = $2
	`, id, tenantID)

	return scanSigmaRule(row)
}

func UpdateSigmaRule(id string, rule models.SigmaRule, tenantID int) error {

	keywordsJSON, _ := json.Marshal(rule.Keywords)
	selectionsJSON, _ := json.Marshal(rule.Selections)

	tag, err := database.DB.Exec(`
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
		WHERE id = $10 AND tenant_id = $11
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
		tenantID,
	)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrSigmaRuleNotFound
	}
	return nil
}

func DeleteSigmaRule(id string, tenantID int) error {

	tag, err := database.DB.Exec(`
		DELETE FROM sigma_rules
		WHERE id = $1 AND tenant_id = $2
	`, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrSigmaRuleNotFound
	}
	return nil
}

func EnableRule(id string, tenantID int) error {

	tag, err := database.DB.Exec(`
		UPDATE sigma_rules
		SET enabled = true
		WHERE id = $1 AND tenant_id = $2
	`, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrSigmaRuleNotFound
	}
	return nil
}

func DisableRule(id string, tenantID int) error {

	tag, err := database.DB.Exec(`
		UPDATE sigma_rules
		SET enabled = false
		WHERE id = $1 AND tenant_id = $2
	`, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrSigmaRuleNotFound
	}
	return nil
}

// GetEnabledRules returns enabled rules for tenantID — used by the rule
// tester, which has a real per-request tenant context from the caller's JWT.
func GetEnabledRules(tenantID int) ([]models.SigmaRule, error) {

	rows, err := database.DB.Query(`
		SELECT `+sigmaSelectCols+`
		FROM sigma_rules
		WHERE enabled = true AND tenant_id = $1
	`, tenantID)

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

// GetEnabledRulesForAgent returns enabled rules for the tenant that owns
// agentID — used by the detection engine, which only has an agent_id to
// work from (no per-request tenant context), so the tenant is resolved via
// the agent in the same query rather than a separate round trip.
func GetEnabledRulesForAgent(agentID int) ([]models.SigmaRule, error) {

	rows, err := database.DB.Query(`
		SELECT `+sigmaSelectCols+`
		FROM sigma_rules
		WHERE enabled = true
		  AND tenant_id = (SELECT tenant_id FROM agents WHERE id = $1)
	`, agentID)

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
