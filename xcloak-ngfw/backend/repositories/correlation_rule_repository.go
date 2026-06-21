package repositories

import (
	"xcloak-ngfw/database"
)

// EnabledCorrelationRule is the subset of correlation_rules columns the
// evaluator needs to test a rule's conditions against an incoming alert.
type EnabledCorrelationRule struct {
	ID             int
	Severity       string
	RuleName       string
	MitreTechnique string
	AgentID        int
	Action         string
	PlaybookID     int
}

// GetEnabledCorrelationRules returns every enabled correlation rule for a
// tenant, for evaluation against a freshly-created alert.
func GetEnabledCorrelationRules(tenantID int) ([]EnabledCorrelationRule, error) {
	rows, err := database.DB.Query(`
		SELECT id, severity, rule_name, mitre_technique, agent_id, action,
		       COALESCE(playbook_id, 0)
		FROM correlation_rules
		WHERE tenant_id = $1 AND enabled = true
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []EnabledCorrelationRule
	for rows.Next() {
		var r EnabledCorrelationRule
		if err := rows.Scan(&r.ID, &r.Severity, &r.RuleName, &r.MitreTechnique, &r.AgentID, &r.Action, &r.PlaybookID); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// IncrementCorrelationRuleMatchCount records that a rule fired.
func IncrementCorrelationRuleMatchCount(id int) error {
	_, err := database.DB.Exec(`UPDATE correlation_rules SET match_count = match_count + 1 WHERE id = $1`, id)
	return err
}

// GetTenantIDByAgentID resolves the owning tenant for an agent — the
// correlation evaluator only has an agent_id (from the alert), not a
// trusted tenant_id, the same reasoning CreateAlert/CreateIncident use.
func GetTenantIDByAgentID(agentID int) (int, error) {
	var tenantID int
	err := database.DB.QueryRow(`SELECT tenant_id FROM agents WHERE id = $1`, agentID).Scan(&tenantID)
	return tenantID, err
}
