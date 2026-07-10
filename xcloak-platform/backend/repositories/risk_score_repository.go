package repositories

import (
	"xcloak-platform/database"
	"xcloak-platform/models"
)

func UpsertRiskScore(
	score models.AssetRiskScore,
) error {

	_, err := database.DB.Exec(`
		INSERT INTO asset_risk_scores
		(
			agent_id,
			risk_score,
			risk_level
		)
		VALUES ($1,$2,$3)

		ON CONFLICT (agent_id)

		DO UPDATE SET

		risk_score = EXCLUDED.risk_score,
		risk_level = EXCLUDED.risk_level,
		updated_at = NOW()
	`,
		score.AgentID,
		score.RiskScore,
		score.RiskLevel,
	)

	return err
}

// GetRiskScoresByTenant returns the risk score for every agent in tenantID
// that has one computed. Agents without a row yet (never scanned) are simply
// absent — callers should treat a missing entry as "unknown", not zero risk.
func GetRiskScoresByTenant(tenantID int) ([]models.AssetRiskScore, error) {

	rows, err := database.DB.Query(`
		SELECT s.id, s.agent_id, s.risk_score, s.risk_level, s.updated_at
		FROM asset_risk_scores s
		JOIN agents a ON a.id = s.agent_id
		WHERE a.tenant_id = $1
	`, tenantID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.AssetRiskScore
	for rows.Next() {
		var s models.AssetRiskScore
		if err := rows.Scan(&s.ID, &s.AgentID, &s.RiskScore, &s.RiskLevel, &s.UpdatedAt); err == nil {
			out = append(out, s)
		}
	}
	return out, nil
}

func GetRiskScore(
	agentID string,
) (*models.AssetRiskScore, error) {

	var score models.AssetRiskScore

	err := database.DB.QueryRow(`
		SELECT
			id,
			agent_id,
			risk_score,
			risk_level,
			updated_at
		FROM asset_risk_scores
		WHERE agent_id=$1
	`,
		agentID,
	).Scan(
		&score.ID,
		&score.AgentID,
		&score.RiskScore,
		&score.RiskLevel,
		&score.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &score, nil
}
