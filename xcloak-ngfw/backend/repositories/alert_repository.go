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
			log_message
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
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

func GetAlerts() ([]models.Alert, error) {

	rows, err := database.DB.Query(`
	SELECT
		id,
		agent_id,
		severity,
		rule_name,
		fingerprint,
		mitre_tactic,
		mitre_technique,
		mitre_name,
		log_message,
		created_at
		FROM alerts
		ORDER BY created_at DESC
	`)

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
