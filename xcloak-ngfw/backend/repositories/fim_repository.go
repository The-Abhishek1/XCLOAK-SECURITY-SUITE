package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// GetFIMBaseline returns all tracked files for an agent.
func GetFIMBaseline(agentID int) ([]models.FIMBaseline, error) {

	rows, err := database.DB.Query(`
		SELECT id, agent_id, file_path, sha256_hash, file_size, created_at
		FROM fim_baselines WHERE agent_id = $1
	`, agentID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var baselines []models.FIMBaseline
	for rows.Next() {
		var b models.FIMBaseline
		if err := rows.Scan(&b.ID, &b.AgentID, &b.FilePath, &b.SHA256, &b.FileSize, &b.CreatedAt); err == nil {
			baselines = append(baselines, b)
		}
	}
	return baselines, nil
}

// UpsertFIMEntry creates or updates a single baseline entry.
func UpsertFIMEntry(b models.FIMBaseline) error {
	_, err := database.DB.Exec(`
		INSERT INTO fim_baselines (agent_id, file_path, sha256_hash, file_size)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (agent_id, file_path) DO UPDATE
		SET sha256_hash = EXCLUDED.sha256_hash,
		    file_size   = EXCLUDED.file_size,
		    created_at  = now()
	`, b.AgentID, b.FilePath, b.SHA256, b.FileSize)
	return err
}

// CreateFIMAlert records a file integrity violation.
func CreateFIMAlert(a models.FIMAlert) error {
	_, err := database.DB.Exec(`
		INSERT INTO fim_alerts (agent_id, file_path, change_type, old_hash, new_hash)
		VALUES ($1,$2,$3,$4,$5)
	`, a.AgentID, a.FilePath, a.ChangeType, a.OldHash, a.NewHash)
	return err
}

// GetFIMAlerts returns recent FIM alerts for an agent.
func GetFIMAlerts(agentID string) ([]models.FIMAlert, error) {

	rows, err := database.DB.Query(`
		SELECT id, agent_id, file_path, change_type, old_hash, new_hash, created_at
		FROM fim_alerts WHERE agent_id = $1
		ORDER BY created_at DESC LIMIT 100
	`, agentID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []models.FIMAlert
	for rows.Next() {
		var a models.FIMAlert
		if err := rows.Scan(&a.ID, &a.AgentID, &a.FilePath, &a.ChangeType, &a.OldHash, &a.NewHash, &a.CreatedAt); err == nil {
			alerts = append(alerts, a)
		}
	}
	return alerts, nil
}
