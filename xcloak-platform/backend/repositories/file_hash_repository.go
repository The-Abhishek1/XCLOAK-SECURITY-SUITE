package repositories

import (
	"xcloak-platform/database"
	"xcloak-platform/models"
)

// SaveFileHashes upserts a batch of file hashes.
// Uses ON CONFLICT to update if the same agent+path was already recorded,
// so re-scans reflect changes (file replaced by malware).
func SaveFileHashes(hashes []models.FileHash) error {

	tx, err := database.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, hash := range hashes {

		_, err := tx.Exec(`
			INSERT INTO endpoint_file_hashes
			(
				agent_id,
				file_path,
				file_name,
				md5_hash,
				sha256_hash,
				file_size
			)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (agent_id, file_path)
			DO UPDATE SET
				file_name   = EXCLUDED.file_name,
				md5_hash    = EXCLUDED.md5_hash,
				sha256_hash = EXCLUDED.sha256_hash,
				file_size   = EXCLUDED.file_size,
				collected_at = NOW()
		`,
			hash.AgentID,
			hash.FilePath,
			hash.FileName,
			hash.MD5Hash,
			hash.SHA256Hash,
			hash.FileSize,
		)

		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetFileHashesByAgent returns all hashes collected for a given agent,
// newest scan first.
func GetFileHashesByAgent(agentID string) ([]models.FileHash, error) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			agent_id,
			file_path,
			file_name,
			md5_hash,
			sha256_hash,
			file_size,
			collected_at
		FROM endpoint_file_hashes
		WHERE agent_id = $1
		ORDER BY collected_at DESC
	`, agentID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	hashes := []models.FileHash{}

	for rows.Next() {

		var h models.FileHash

		err := rows.Scan(
			&h.ID,
			&h.AgentID,
			&h.FilePath,
			&h.FileName,
			&h.MD5Hash,
			&h.SHA256Hash,
			&h.FileSize,
			&h.CollectedAt,
		)

		if err != nil {
			continue
		}

		hashes = append(hashes, h)
	}

	return hashes, nil
}

// GetFileHashCount returns total number of hashes stored for an agent.
func GetFileHashCount(agentID string) (int, error) {

	var count int

	err := database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM endpoint_file_hashes
		WHERE agent_id = $1
	`, agentID).Scan(&count)

	return count, err
}
