package repositories

import (
	"xcloak-platform/database"
	"xcloak-platform/models"
)

// CreateCorrelationMatch records one firing of a correlation rule — the
// audit trail match_count alone never provided.
func CreateCorrelationMatch(m models.CorrelationMatch) error {
	_, err := database.DB.Exec(`
		INSERT INTO correlation_matches
		  (rule_id, tenant_id, agent_id, trigger_alert_id, incident_id, confidence, detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, m.RuleID, m.TenantID, m.AgentID, m.TriggerAlertID, m.IncidentID, m.Confidence, m.Detail)
	return err
}

// GetCorrelationMatches returns recent match history for a tenant, newest
// first. ruleID == 0 returns matches across every rule for the tenant.
func GetCorrelationMatches(tenantID, ruleID, limit int) ([]models.CorrelationMatch, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := database.DB.Query(`
		SELECT m.id, m.rule_id, r.name, m.agent_id, COALESCE(a.hostname, ''),
		       m.trigger_alert_id, m.incident_id, m.confidence, m.detail, m.matched_at
		FROM correlation_matches m
		JOIN correlation_rules r ON r.id = m.rule_id
		LEFT JOIN agents a ON a.id = m.agent_id
		WHERE m.tenant_id = $1 AND ($2 = 0 OR m.rule_id = $2)
		ORDER BY m.matched_at DESC
		LIMIT $3
	`, tenantID, ruleID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []models.CorrelationMatch{}
	for rows.Next() {
		var m models.CorrelationMatch
		if err := rows.Scan(&m.ID, &m.RuleID, &m.RuleName, &m.AgentID, &m.Hostname,
			&m.TriggerAlertID, &m.IncidentID, &m.Confidence, &m.Detail, &m.MatchedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
