package repositories

import (
	"xcloak-platform/database"
)

func SaveCollectedFile(
	agentID int,
	originalPath string,
	fileName string,
	storedPath string,
) error {

	_, err := database.DB.Exec(`
		INSERT INTO collected_files
		(agent_id,
		 original_path,
		 file_name,
		 stored_path)
		VALUES ($1,$2,$3,$4)
	`,
		agentID,
		originalPath,
		fileName,
		storedPath,
	)

	return err
}
