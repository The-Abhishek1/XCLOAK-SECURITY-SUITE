package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func CreateAuditLog(
	action string,
	details string,
	username string,
) error {

	query := `
	INSERT INTO audit_logs
	(action, details, username)
	VALUES ($1,$2,$3)
	`

	_, err := database.DB.Exec(
		query,
		action,
		details,
		username,
	)

	return err
}

func GetAuditLogs() ([]models.AuditLog, error) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			action,
			details,
			username,
			created_at
		FROM audit_logs
		ORDER BY created_at DESC
	`)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var logs []models.AuditLog

	for rows.Next() {

		var log models.AuditLog

		err := rows.Scan(
			&log.ID,
			&log.Action,
			&log.Details,
			&log.Username,
			&log.CreatedAt,
		)

		if err != nil {
			continue
		}

		logs = append(logs, log)
	}

	return logs, nil
}
