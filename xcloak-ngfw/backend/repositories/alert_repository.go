package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func CreateAlert(
	alert models.Alert,
) error {

	if AlertExists(
		alert.Fingerprint,
	) {

		return nil
	}

	// tenant_id is resolved from the owning agent rather than taken from
	// alert.TenantID — CreateAlert is called from detection engines
	// (sigma/ioc/yara matching) that only carry agent_id, and the agent is
	// the single source of truth for which tenant an alert belongs to.
	_, err := database.DB.Exec(`
		INSERT INTO alerts
		(
			agent_id,
			severity,
			rule_name,
			fingerprint,
			mitre_tactic,
			mitre_technique,
			mitre_name,
			log_message,
			tenant_id
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8, (SELECT tenant_id FROM agents WHERE id = $1))
	`,
		alert.AgentID,
		alert.Severity,
		alert.RuleName,
		alert.Fingerprint,
		alert.MitreTactic,
		alert.MitreTechnique,
		alert.MitreName,
		alert.LogMessage,
	)

	return err
}

// GetAlerts returns alerts belonging to tenantID only. Use this from
// user-facing API paths that have a real tenant context from the request.
func GetAlerts(tenantID int) ([]models.Alert, error) {
	return queryAlerts(`
		SELECT id, agent_id, severity, rule_name, fingerprint,
		       mitre_tactic, mitre_technique, mitre_name, log_message, created_at, tenant_id
		FROM alerts
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`, tenantID)
}

// GetAllAlerts returns every alert across every tenant. For internal
// background jobs (AI chat/triage, compliance, risk scoring) that operate
// fleet-wide with no per-request tenant context — not for user-facing API
// responses, which must use GetAlerts(tenantID) instead.
func GetAllAlerts() ([]models.Alert, error) {
	return queryAlerts(`
		SELECT id, agent_id, severity, rule_name, fingerprint,
		       mitre_tactic, mitre_technique, mitre_name, log_message, created_at, tenant_id
		FROM alerts
		ORDER BY created_at DESC
	`)
}

func queryAlerts(query string, args ...interface{}) ([]models.Alert, error) {

	rows, err := database.DB.Query(query, args...)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var alerts []models.Alert

	for rows.Next() {

		var alert models.Alert

		err := rows.Scan(
			&alert.ID,
			&alert.AgentID,
			&alert.Severity,
			&alert.RuleName,
			&alert.Fingerprint,
			&alert.MitreTactic,
			&alert.MitreTechnique,
			&alert.MitreName,
			&alert.LogMessage,
			&alert.CreatedAt,
			&alert.TenantID,
		)

		if err != nil {
			continue
		}

		alerts = append(alerts, alert)
	}

	return alerts, nil
}

func AlertExists(
	fingerprint string,
) bool {

	var count int

	err := database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM alerts
		WHERE
			fingerprint = $1
			AND created_at >
			NOW() - INTERVAL '10 minutes'
	`,
		fingerprint,
	).Scan(&count)

	if err != nil {
		return false
	}

	return count > 0
}
