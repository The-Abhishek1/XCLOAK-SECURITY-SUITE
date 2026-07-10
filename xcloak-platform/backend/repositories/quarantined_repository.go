package repositories

import (
	"xcloak-platform/database"
	"xcloak-platform/models"
)

// SaveQuarantinedFile inserts a quarantine record with tenant_id resolved
// from the owning agent — same pattern as CreateAlert.
func SaveQuarantinedFile(
	file models.QuarantinedFile,
) error {

	_, err := database.DB.Exec(`
		INSERT INTO quarantined_files
		(
			agent_id,
			original_path,
			quarantine_path,
			file_name,
			reason,
			tenant_id
		)
		VALUES ($1,$2,$3,$4,$5, (SELECT tenant_id FROM agents WHERE id = $1))
	`,
		file.AgentID,
		file.OriginalPath,
		file.QuarantinePath,
		file.FileName,
		file.Reason,
	)

	return err
}

// GetQuarantinedFiles returns quarantine records belonging to tenantID only.
func GetQuarantinedFiles(tenantID int) ([]models.QuarantinedFile, error) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			agent_id,
			original_path,
			quarantine_path,
			file_name,
			reason,
			quarantined_at
		FROM quarantined_files
		WHERE tenant_id = $1
		ORDER BY quarantined_at DESC
	`, tenantID)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var files []models.QuarantinedFile

	for rows.Next() {

		var file models.QuarantinedFile

		err := rows.Scan(
			&file.ID,
			&file.AgentID,
			&file.OriginalPath,
			&file.QuarantinePath,
			&file.FileName,
			&file.Reason,
			&file.QuarantinedAt,
		)

		if err != nil {
			continue
		}

		files = append(files, file)
	}

	return files, nil
}
