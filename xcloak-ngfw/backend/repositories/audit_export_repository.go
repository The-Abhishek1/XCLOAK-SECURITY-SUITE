package repositories

import (
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// GetAuditLogsAfter returns up to limit audit_logs rows with id > afterID,
// ordered oldest-first so exported batches stay chronological.
func GetAuditLogsAfter(afterID, limit int) ([]models.AuditLog, error) {
	rows, err := database.DB.Query(`
		SELECT id, action, details, username, created_at
		FROM audit_logs
		WHERE id > $1
		ORDER BY id ASC
		LIMIT $2
	`, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []models.AuditLog
	for rows.Next() {
		var l models.AuditLog
		if err := rows.Scan(&l.ID, &l.Action, &l.Details, &l.Username, &l.CreatedAt); err == nil {
			logs = append(logs, l)
		}
	}
	return logs, nil
}

// GetAuditExportCursor returns the id of the last successfully exported
// audit_logs row (0 if nothing has been exported yet).
func GetAuditExportCursor() (int, error) {
	var lastID int
	err := database.DB.QueryRow(`SELECT last_exported_id FROM audit_export_cursor WHERE id = 1`).Scan(&lastID)
	return lastID, err
}

// UpdateAuditExportCursor advances the cursor after a batch is durably
// written to object storage.
func UpdateAuditExportCursor(lastID int, objectKey string) error {
	_, err := database.DB.Exec(`
		UPDATE audit_export_cursor
		SET last_exported_id = $1, last_exported_at = $2, last_object_key = $3
		WHERE id = 1
	`, lastID, time.Now(), objectKey)
	return err
}

// GetAuditExportStatus returns the cursor row for the status API.
func GetAuditExportStatus() (lastID int, lastAt *time.Time, lastKey string, err error) {
	err = database.DB.QueryRow(`
		SELECT last_exported_id, last_exported_at, COALESCE(last_object_key, '')
		FROM audit_export_cursor WHERE id = 1
	`).Scan(&lastID, &lastAt, &lastKey)
	return
}
