package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

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
			reason
		)
		VALUES ($1,$2,$3,$4,$5)
	`,
		file.AgentID,
		file.OriginalPath,
		file.QuarantinePath,
		file.FileName,
		file.Reason,
	)

	return err
}

func GetQuarantinedFiles() ([]models.QuarantinedFile, error) {

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
		ORDER BY quarantined_at DESC
	`)

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
