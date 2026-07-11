package repositories

import (
	"xcloak-platform/database"
	"xcloak-platform/models"
)

// GetFIMBaseline returns all tracked files for an agent.
func GetFIMBaseline(agentID int) ([]models.FIMBaseline, error) {
	rows, err := database.DB.Query(`
		SELECT id, agent_id, file_path, sha256_hash, file_size,
		       COALESCE(file_mode,''), COALESCE(file_uid,0), COALESCE(file_gid,0),
		       mod_time, created_at
		FROM fim_baselines WHERE agent_id = $1
	`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var baselines []models.FIMBaseline
	for rows.Next() {
		var b models.FIMBaseline
		if err := rows.Scan(
			&b.ID, &b.AgentID, &b.FilePath, &b.SHA256, &b.FileSize,
			&b.FileMode, &b.FileUID, &b.FileGID,
			&b.ModTime, &b.CreatedAt,
		); err == nil {
			baselines = append(baselines, b)
		}
	}
	return baselines, nil
}

// UpsertFIMEntry creates or updates a single baseline entry, including
// permission and ownership fields when the agent provides them.
func UpsertFIMEntry(b models.FIMBaseline) error {
	_, err := database.DB.Exec(`
		INSERT INTO fim_baselines (agent_id, file_path, sha256_hash, file_size, file_mode, file_uid, file_gid, mod_time)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (agent_id, file_path) DO UPDATE
		SET sha256_hash = EXCLUDED.sha256_hash,
		    file_size   = EXCLUDED.file_size,
		    file_mode   = EXCLUDED.file_mode,
		    file_uid    = EXCLUDED.file_uid,
		    file_gid    = EXCLUDED.file_gid,
		    mod_time    = EXCLUDED.mod_time,
		    created_at  = now()
	`, b.AgentID, b.FilePath, b.SHA256, b.FileSize, b.FileMode, b.FileUID, b.FileGID, b.ModTime)
	return err
}

// DeleteFIMEntry removes a baseline entry — used when accepting a
// "deleted" FIM change, since there's no longer a file to track.
func DeleteFIMEntry(agentID int, filePath string) error {
	_, err := database.DB.Exec(`DELETE FROM fim_baselines WHERE agent_id = $1 AND file_path = $2`, agentID, filePath)
	return err
}

// GetLatestFIMAlert returns the most recent FIM alert for one file, or nil
// if there isn't one.
func GetLatestFIMAlert(agentID int, filePath string) (*models.FIMAlert, error) {
	var a models.FIMAlert
	err := database.DB.QueryRow(`
		SELECT id, agent_id, file_path, change_type, old_hash, new_hash,
		       COALESCE(old_mode,''), COALESCE(new_mode,''),
		       COALESCE(old_uid,0),  COALESCE(new_uid,0),
		       created_at
		FROM fim_alerts WHERE agent_id = $1 AND file_path = $2
		ORDER BY created_at DESC LIMIT 1
	`, agentID, filePath).Scan(
		&a.ID, &a.AgentID, &a.FilePath, &a.ChangeType, &a.OldHash, &a.NewHash,
		&a.OldMode, &a.NewMode, &a.OldUID, &a.NewUID,
		&a.CreatedAt,
	)
	if err != nil {
		return nil, nil
	}
	return &a, nil
}

// CreateFIMAlert records a file integrity violation, including any
// permission or ownership changes that were detected alongside it.
func CreateFIMAlert(a models.FIMAlert) error {
	_, err := database.DB.Exec(`
		INSERT INTO fim_alerts
		  (agent_id, file_path, change_type, old_hash, new_hash, old_mode, new_mode, old_uid, new_uid)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, a.AgentID, a.FilePath, a.ChangeType, a.OldHash, a.NewHash,
		a.OldMode, a.NewMode, a.OldUID, a.NewUID)
	return err
}

// GetFIMAlerts returns recent FIM alerts for an agent.
func GetFIMAlerts(agentID string) ([]models.FIMAlert, error) {
	rows, err := database.DB.Query(`
		SELECT id, agent_id, file_path, change_type, old_hash, new_hash,
		       COALESCE(old_mode,''), COALESCE(new_mode,''),
		       COALESCE(old_uid,0),  COALESCE(new_uid,0),
		       created_at
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
		if err := rows.Scan(
			&a.ID, &a.AgentID, &a.FilePath, &a.ChangeType, &a.OldHash, &a.NewHash,
			&a.OldMode, &a.NewMode, &a.OldUID, &a.NewUID,
			&a.CreatedAt,
		); err == nil {
			alerts = append(alerts, a)
		}
	}
	return alerts, nil
}
