package repositories

import (
	"context"
	"database/sql"
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

	// yara_matches has no rule_id column at all — the agent's YARA engine
	// only ever reports a matched rule's declared *name* (that's inherent to
	// how YARA scanning works), so every match-history query joins on
	// rule_name instead. Renaming a rule here without also updating its
	// past matches silently orphaned all of that rule's history from its
	// own detail page (verified live: match_count dropped from 1 to 0
	// immediately after a rename, with zero warning to the user, while the
	// matches remained visible elsewhere e.g. the global Matches tab).
	// Cascade the rename inside the same transaction so history follows it.
	err := database.WithTenantTx(context.Background(), tenantID, func(tx *sql.Tx) error {
		var oldName string
		if err := tx.QueryRow(`SELECT name FROM yara_rules WHERE id=$1 AND tenant_id=$2`, id, tenantID).Scan(&oldName); err != nil {
			return ErrYaraRuleNotFound
		}

		tag, err := tx.Exec(`
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

		if oldName != rule.Name {
			_, err = tx.Exec(`UPDATE yara_matches SET rule_name=$1 WHERE rule_name=$2 AND tenant_id=$3`, rule.Name, oldName, tenantID)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
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
