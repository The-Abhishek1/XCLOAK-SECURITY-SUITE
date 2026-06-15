package services

import (
	"fmt"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

type SuppressionRule struct {
	ID             int        `json:"id"`
	Name           string     `json:"name"`
	Description    string     `json:"description"`
	RuleName       string     `json:"rule_name"`
	AgentID        int        `json:"agent_id"`
	Severity       string     `json:"severity"`
	MitreTechnique string     `json:"mitre_technique"`
	WindowMinutes  int        `json:"window_minutes"`
	ExpiresAt      *time.Time `json:"expires_at"`
	Enabled        bool       `json:"enabled"`
	MatchCount     int        `json:"match_count"`
	CreatedBy      string     `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
}

// IsSuppressed returns true if the alert should be dropped by any active rule.
// Also updates match counts and suppression state in the DB.
func IsSuppressed(alert models.Alert) bool {

	rows, err := database.DB.Query(`
		SELECT id, rule_name, agent_id, severity, mitre_technique, window_minutes, expires_at
		FROM suppression_rules
		WHERE enabled = TRUE
		AND (expires_at IS NULL OR expires_at > now())
	`)
	if err != nil {
		return false
	}
	defer rows.Close()

	for rows.Next() {
		var r struct {
			ID             int
			RuleName       string
			AgentID        int
			Severity       string
			MitreTechnique string
			WindowMinutes  int
			ExpiresAt      *time.Time
		}

		if err := rows.Scan(&r.ID, &r.RuleName, &r.AgentID, &r.Severity,
			&r.MitreTechnique, &r.WindowMinutes, &r.ExpiresAt); err != nil {
			continue
		}

		if !matchesSuppression(alert, r.RuleName, r.AgentID, r.Severity, r.MitreTechnique) {
			continue
		}

		// Check if within suppression window.
		var lastMatched time.Time
		err := database.DB.QueryRow(`
			SELECT last_matched FROM suppression_state
			WHERE suppression_id=$1 AND agent_id=$2 AND rule_name=$3
		`, r.ID, alert.AgentID, alert.RuleName).Scan(&lastMatched)

		inWindow := err == nil && time.Since(lastMatched) < time.Duration(r.WindowMinutes)*time.Minute

		if inWindow {
			// Still in window — suppress and increment counter.
			database.DB.Exec(`
				UPDATE suppression_rules SET match_count = match_count + 1 WHERE id=$1`, r.ID)
			return true
		}

		// First match or window expired — record state, let this one through.
		database.DB.Exec(`
			INSERT INTO suppression_state (suppression_id, agent_id, rule_name, last_matched)
			VALUES ($1,$2,$3,now())
			ON CONFLICT (suppression_id, agent_id, rule_name)
			DO UPDATE SET last_matched = now()
		`, r.ID, alert.AgentID, alert.RuleName)
		database.DB.Exec(`
			UPDATE suppression_rules SET match_count = match_count + 1 WHERE id=$1`, r.ID)

		// First occurrence passes through — subsequent ones in the window are suppressed.
		return false
	}

	return false
}

func matchesSuppression(alert models.Alert, ruleName string, agentID int, severity, mitre string) bool {
	if ruleName != "" && !strings.Contains(strings.ToLower(alert.RuleName), strings.ToLower(ruleName)) {
		return false
	}
	if agentID != 0 && alert.AgentID != agentID {
		return false
	}
	if severity != "" && !strings.EqualFold(alert.Severity, severity) {
		return false
	}
	if mitre != "" && !strings.EqualFold(alert.MitreTechnique, mitre) {
		return false
	}
	return true
}

func GetSuppressionRules() ([]SuppressionRule, error) {
	rows, err := database.DB.Query(`
		SELECT id, name, description, rule_name, agent_id, severity, mitre_technique,
		       window_minutes, expires_at, enabled, match_count, created_by, created_at
		FROM suppression_rules ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []SuppressionRule
	for rows.Next() {
		var r SuppressionRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.RuleName, &r.AgentID,
			&r.Severity, &r.MitreTechnique, &r.WindowMinutes, &r.ExpiresAt,
			&r.Enabled, &r.MatchCount, &r.CreatedBy, &r.CreatedAt); err == nil {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

func CreateSuppressionRule(r SuppressionRule) (*SuppressionRule, error) {
	err := database.DB.QueryRow(`
		INSERT INTO suppression_rules
		(name, description, rule_name, agent_id, severity, mitre_technique,
		 window_minutes, expires_at, enabled, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,TRUE,$9)
		RETURNING id, created_at
	`, r.Name, r.Description, r.RuleName, r.AgentID, r.Severity,
		r.MitreTechnique, r.WindowMinutes, r.ExpiresAt, r.CreatedBy).
		Scan(&r.ID, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func DeleteSuppressionRule(id string) error {
	_, err := database.DB.Exec(`DELETE FROM suppression_rules WHERE id=$1`, id)
	return err
}

func ToggleSuppressionRule(id string, enabled bool) error {
	_, err := database.DB.Exec(
		`UPDATE suppression_rules SET enabled=$1 WHERE id=$2`, enabled, id)
	return err
}

// GetSuppressionStats returns alert counts with/without suppression for a quick view.
func GetSuppressionStats() map[string]int {
	stats := map[string]int{}
	database.DB.QueryRow(`SELECT COUNT(*) FROM suppression_rules WHERE enabled=TRUE`).Scan(&stats["active_rules"])
	database.DB.QueryRow(`SELECT COALESCE(SUM(match_count),0) FROM suppression_rules`).Scan(&stats["total_suppressed"])
	return stats
}

// Silence unused import
var _ = fmt.Sprintf
