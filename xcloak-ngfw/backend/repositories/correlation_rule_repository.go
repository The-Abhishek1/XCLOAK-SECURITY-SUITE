package repositories

import (
	"time"

	"xcloak-ngfw/database"
)

// EnabledCorrelationRule is the subset of correlation_rules columns the
// evaluator needs. Stages is only populated for "temporal"/"temporal_ordered"
// rule types (see CorrelationType) — "simple" and "event_count" rules use
// the single Severity/RuleName/MitreTechnique/AgentID condition instead.
type EnabledCorrelationRule struct {
	ID               int
	Severity         string
	RuleName         string
	MitreTechnique   string
	AgentID          int
	Action           string
	PlaybookID       int
	CorrelationType  string // "simple" | "event_count" | "temporal" | "temporal_ordered"
	WindowMinutes    int
	Threshold        int
	Stages           []string // ordered rule_name patterns, for temporal types
}

// GetEnabledCorrelationRules returns every enabled correlation rule for a
// tenant, for evaluation against a freshly-created alert.
func GetEnabledCorrelationRules(tenantID int) ([]EnabledCorrelationRule, error) {
	rows, err := database.DB.Query(`
		SELECT id, severity, rule_name, mitre_technique, agent_id, action,
		       COALESCE(playbook_id, 0), correlation_type, window_minutes, threshold
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
		if err := rows.Scan(&r.ID, &r.Severity, &r.RuleName, &r.MitreTechnique, &r.AgentID, &r.Action,
			&r.PlaybookID, &r.CorrelationType, &r.WindowMinutes, &r.Threshold); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for i := range rules {
		if rules[i].CorrelationType == "temporal" || rules[i].CorrelationType == "temporal_ordered" {
			stages, err := GetCorrelationRuleStages(rules[i].ID)
			if err != nil {
				return nil, err
			}
			rules[i].Stages = stages
		}
	}

	return rules, nil
}

// GetCorrelationRuleStages returns a rule's ordered stage patterns.
func GetCorrelationRuleStages(ruleID int) ([]string, error) {
	rows, err := database.DB.Query(`
		SELECT rule_name_pattern FROM correlation_rule_stages
		WHERE rule_id = $1 ORDER BY stage_order ASC
	`, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stages []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		stages = append(stages, s)
	}
	return stages, rows.Err()
}

// ReplaceCorrelationRuleStages deletes and re-inserts a rule's stage list —
// used on both create and update so editing a temporal rule's stages is a
// single atomic replace rather than a diff.
func ReplaceCorrelationRuleStages(ruleID int, stages []string) error {
	tx, err := database.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM correlation_rule_stages WHERE rule_id = $1`, ruleID); err != nil {
		return err
	}
	for i, pattern := range stages {
		if pattern == "" {
			continue
		}
		if _, err := tx.Exec(`
			INSERT INTO correlation_rule_stages (rule_id, stage_order, rule_name_pattern)
			VALUES ($1, $2, $3)
		`, ruleID, i, pattern); err != nil {
			return err
		}
	}
	return tx.Commit()
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

// CountRecentMatchingAlerts counts how many alerts for agentID within the
// last windowMinutes satisfy the rule's own simple conditions (severity /
// rule_name substring / mitre_technique) — the building block for
// "event_count" correlation rules (N+ occurrences within a window).
func CountRecentMatchingAlerts(agentID int, severity, ruleNamePattern, mitreTechnique string, windowMinutes int) (int, error) {
	var count int
	err := database.DB.QueryRow(`
		SELECT COUNT(*) FROM alerts
		WHERE agent_id = $1
		  AND created_at > now() - ($2 || ' minutes')::interval
		  AND ($3 = '' OR severity = $3)
		  AND ($4 = '' OR rule_name ILIKE '%' || $4 || '%')
		  AND ($5 = '' OR mitre_technique = $5)
	`, agentID, windowMinutes, severity, ruleNamePattern, mitreTechnique).Scan(&count)
	return count, err
}

// RecentRuleFirstSeen returns, for every distinct rule_name that fired for
// agentID within the last windowMinutes, the earliest time it fired — the
// building block for "temporal"/"temporal_ordered" correlation rules
// (do all of these stage patterns appear within the window, and in order?).
func RecentRuleFirstSeen(agentID int, windowMinutes int) (map[string]time.Time, error) {
	rows, err := database.DB.Query(`
		SELECT rule_name, MIN(created_at)
		FROM alerts
		WHERE agent_id = $1 AND created_at > now() - ($2 || ' minutes')::interval
		GROUP BY rule_name
	`, agentID, windowMinutes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]time.Time{}
	for rows.Next() {
		var name string
		var t time.Time
		if err := rows.Scan(&name, &t); err != nil {
			return nil, err
		}
		out[name] = t
	}
	return out, rows.Err()
}
