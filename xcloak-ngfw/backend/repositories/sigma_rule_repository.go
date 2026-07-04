package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

type SigmaPage struct {
	Data  []models.SigmaRule `json:"data"`
	Total int                `json:"total"`
	Page  int                `json:"page"`
	Limit int                `json:"limit"`
}

func GetSigmaRulesPaged(tenantID, page, limit int, search, severity string) (SigmaPage, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * limit

	where := "WHERE tenant_id = $1"
	args := []interface{}{tenantID}
	i := 2

	if severity != "" && severity != "all" {
		where += fmt.Sprintf(" AND severity = $%d", i)
		args = append(args, severity)
		i++
	}
	if search != "" {
		where += fmt.Sprintf(" AND (title ILIKE $%d OR description ILIKE $%d)", i, i)
		args = append(args, "%"+strings.TrimSpace(search)+"%")
		i++
	}

	var total int
	if err := database.DB.QueryRow(`SELECT COUNT(*) FROM sigma_rules `+where, args...).Scan(&total); err != nil {
		return SigmaPage{}, err
	}

	rows, err := database.DB.Query(fmt.Sprintf(`
		SELECT `+sigmaSelectCols+`
		FROM sigma_rules %s
		ORDER BY id DESC
		LIMIT $%d OFFSET $%d
	`, where, i, i+1), append(args, limit, offset)...)
	if err != nil {
		return SigmaPage{}, err
	}
	defer rows.Close()
	data, err := collectSigmaRules(rows)
	if err != nil {
		return SigmaPage{}, err
	}
	return SigmaPage{Data: data, Total: total, Page: page, Limit: limit}, nil
}

var ErrSigmaRuleNotFound = errors.New("sigma rule not found")

// SigmaRuleStat holds aggregate hit data for one rule.
type SigmaRuleStat struct {
	RuleID        int        `json:"rule_id"`
	Title         string     `json:"title"`
	HitCount      int        `json:"hit_count"`
	LastMatchedAt *time.Time `json:"last_matched_at"`
}

// ─────────────────────────────────────────────────────────────────────────────
// SELECT column list (keep in sync with scanSigmaRule)
// ─────────────────────────────────────────────────────────────────────────────

const sigmaSelectCols = `
	id,
	title,
	COALESCE(description,    ''),
	severity,
	mitre_tactic,
	mitre_technique,
	mitre_name,
	COALESCE(logsource_cat,  ''),
	COALESCE(logsource_prod, ''),
	COALESCE(logsource_svc,  ''),
	COALESCE(status, 'experimental'),
	COALESCE(tags,           '[]'::jsonb),
	COALESCE(falsepositives, '[]'::jsonb),
	COALESCE("references",   '[]'::jsonb),
	keywords,
	COALESCE(selections, '{}'::jsonb),
	COALESCE(condition, ''),
	enabled,
	tenant_id,
	created_at
`

func scanSigmaRule(row interface {
	Scan(dest ...interface{}) error
}) (*models.SigmaRule, error) {

	var rule models.SigmaRule
	var keywords, selections, tags, fp, refs []byte

	err := row.Scan(
		&rule.ID,
		&rule.Title,
		&rule.Description,
		&rule.Severity,
		&rule.MitreTactic,
		&rule.MitreTechnique,
		&rule.MitreName,
		&rule.LogsourceCategory,
		&rule.LogsourceProduct,
		&rule.LogsourceService,
		&rule.Status,
		&tags,
		&fp,
		&refs,
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
	json.Unmarshal(tags, &rule.Tags)
	json.Unmarshal(fp, &rule.FalsePositives)
	json.Unmarshal(refs, &rule.References)

	return &rule, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// CRUD
// ─────────────────────────────────────────────────────────────────────────────

func CreateSigmaRule(rule models.SigmaRule, tenantID int) error {
	keywordsJSON, _ := json.Marshal(rule.Keywords)
	selectionsJSON, _ := json.Marshal(rule.Selections)
	tagsJSON, _ := json.Marshal(orEmptySlice(rule.Tags))
	fpJSON, _ := json.Marshal(orEmptySlice(rule.FalsePositives))
	refsJSON, _ := json.Marshal(orEmptySlice(rule.References))

	return database.WithTenantTx(context.Background(), tenantID, func(tx *sql.Tx) error {
		_, err := tx.Exec(`
			INSERT INTO sigma_rules
			(
				title, description, severity,
				mitre_tactic, mitre_technique, mitre_name,
				logsource_cat, logsource_prod, logsource_svc,
				status, tags, falsepositives, "references",
				keywords, selections, condition, enabled, tenant_id
			)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		`,
			rule.Title, rule.Description, rule.Severity,
			rule.MitreTactic, rule.MitreTechnique, rule.MitreName,
			rule.LogsourceCategory, rule.LogsourceProduct, rule.LogsourceService,
			rule.Status, tagsJSON, fpJSON, refsJSON,
			keywordsJSON, selectionsJSON, rule.Condition, rule.Enabled, tenantID,
		)
		return err
	})
}

func UpdateSigmaRule(id string, rule models.SigmaRule, tenantID int) error {
	keywordsJSON, _ := json.Marshal(rule.Keywords)
	selectionsJSON, _ := json.Marshal(rule.Selections)
	tagsJSON, _ := json.Marshal(orEmptySlice(rule.Tags))
	fpJSON, _ := json.Marshal(orEmptySlice(rule.FalsePositives))
	refsJSON, _ := json.Marshal(orEmptySlice(rule.References))

	return database.WithTenantTx(context.Background(), tenantID, func(tx *sql.Tx) error {
		tag, err := tx.Exec(`
			UPDATE sigma_rules SET
				title          = $1,
				description    = $2,
				severity       = $3,
				mitre_tactic   = $4,
				mitre_technique= $5,
				mitre_name     = $6,
				logsource_cat  = $7,
				logsource_prod = $8,
				logsource_svc  = $9,
				status         = $10,
				tags           = $11,
				falsepositives = $12,
				"references"   = $13,
				keywords       = $14,
				selections     = $15,
				condition      = $16,
				enabled        = $17
			WHERE id = $18 AND tenant_id = $19
		`,
			rule.Title, rule.Description, rule.Severity,
			rule.MitreTactic, rule.MitreTechnique, rule.MitreName,
			rule.LogsourceCategory, rule.LogsourceProduct, rule.LogsourceService,
			rule.Status, tagsJSON, fpJSON, refsJSON,
			keywordsJSON, selectionsJSON, rule.Condition, rule.Enabled,
			id, tenantID,
		)
		if err != nil {
			return err
		}
		if n, _ := tag.RowsAffected(); n == 0 {
			return ErrSigmaRuleNotFound
		}
		return nil
	})
}

func DeleteSigmaRule(id string, tenantID int) error {
	tag, err := database.DB.Exec(`
		DELETE FROM sigma_rules WHERE id = $1 AND tenant_id = $2
	`, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrSigmaRuleNotFound
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Read
// ─────────────────────────────────────────────────────────────────────────────

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
	return collectSigmaRules(rows)
}

func GetSigmaRuleByID(id string, tenantID int) (*models.SigmaRule, error) {
	row := database.DB.QueryRow(`
		SELECT `+sigmaSelectCols+`
		FROM sigma_rules
		WHERE id = $1 AND tenant_id = $2
	`, id, tenantID)
	return scanSigmaRule(row)
}

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
	return collectSigmaRules(rows)
}

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
	return collectSigmaRules(rows)
}

// ─────────────────────────────────────────────────────────────────────────────
// Enable / Disable
// ─────────────────────────────────────────────────────────────────────────────

func EnableRule(id string, tenantID int) error {
	tag, err := database.DB.Exec(`
		UPDATE sigma_rules SET enabled = true WHERE id = $1 AND tenant_id = $2
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
		UPDATE sigma_rules SET enabled = false WHERE id = $1 AND tenant_id = $2
	`, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrSigmaRuleNotFound
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Hit tracking
// ─────────────────────────────────────────────────────────────────────────────

func RecordSigmaHit(ruleID, agentID, tenantID int) error {
	_, err := database.DB.Exec(`
		INSERT INTO sigma_rule_hits (rule_id, agent_id, tenant_id)
		VALUES ($1, $2, $3)
	`, ruleID, agentID, tenantID)
	return err
}

// GetSigmaStats returns hit counts + last match time per rule for a tenant,
// ordered by hit count descending, limited to top 50.
func GetSigmaStats(tenantID int) ([]SigmaRuleStat, error) {
	rows, err := database.DB.Query(`
		SELECT
			sr.id,
			sr.title,
			COUNT(h.id)            AS hit_count,
			MAX(h.matched_at)      AS last_matched_at
		FROM sigma_rules sr
		LEFT JOIN sigma_rule_hits h ON h.rule_id = sr.id AND h.tenant_id = sr.tenant_id
		WHERE sr.tenant_id = $1
		GROUP BY sr.id, sr.title
		ORDER BY hit_count DESC, sr.id
		LIMIT 50
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []SigmaRuleStat
	for rows.Next() {
		var s SigmaRuleStat
		if err := rows.Scan(&s.RuleID, &s.Title, &s.HitCount, &s.LastMatchedAt); err != nil {
			continue
		}
		stats = append(stats, s)
	}
	return stats, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func collectSigmaRules(rows interface {
	Next() bool
	Scan(dest ...interface{}) error
	Close() error
}) ([]models.SigmaRule, error) {
	rules := []models.SigmaRule{}
	for rows.Next() {
		rule, err := scanSigmaRule(rows)
		if err != nil {
			continue
		}
		rules = append(rules, *rule)
	}
	return rules, nil
}

func orEmptySlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
