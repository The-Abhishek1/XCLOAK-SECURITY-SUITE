package repositories

import (
	"encoding/json"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func CreateAsset(a models.Asset) (models.Asset, error) {
	tags, _ := json.Marshal(a.Tags)
	err := database.DB.QueryRow(`
		INSERT INTO assets
		  (tenant_id, agent_id, name, hostname, ip_address, asset_type,
		   owner, business_unit, criticality, data_classification,
		   environment, location, tags, notes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		RETURNING id, created_at, updated_at
	`, a.TenantID, a.AgentID, a.Name, a.Hostname, a.IPAddress, a.AssetType,
		a.Owner, a.BusinessUnit, a.Criticality, a.DataClassification,
		a.Environment, a.Location, tags, a.Notes,
	).Scan(&a.ID, &a.CreatedAt, &a.UpdatedAt)
	return a, err
}

func GetAssets(tenantID int) ([]models.Asset, error) {
	rows, err := database.DB.Query(`
		SELECT a.id, a.tenant_id, a.agent_id, a.name, a.hostname, a.ip_address,
		       a.asset_type, a.owner, a.business_unit, a.criticality,
		       a.data_classification, a.environment, a.location,
		       COALESCE(a.tags,'[]'::jsonb), COALESCE(a.notes,''),
		       COALESCE(ag.status,''), COALESCE(rs.risk_score,0),
		       a.created_at, a.updated_at
		FROM assets a
		LEFT JOIN agents ag ON ag.id = a.agent_id
		LEFT JOIN asset_risk_scores rs ON rs.agent_id = a.agent_id
		WHERE a.tenant_id=$1
		ORDER BY
		  CASE a.criticality WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
		  a.name
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAssets(rows)
}

func GetAssetByID(id, tenantID int) (models.Asset, error) {
	var a models.Asset
	var tagsJSON []byte
	err := database.DB.QueryRow(`
		SELECT a.id, a.tenant_id, a.agent_id, a.name, a.hostname, a.ip_address,
		       a.asset_type, a.owner, a.business_unit, a.criticality,
		       a.data_classification, a.environment, a.location,
		       COALESCE(a.tags,'[]'::jsonb), COALESCE(a.notes,''),
		       COALESCE(ag.status,''), COALESCE(rs.risk_score,0),
		       a.created_at, a.updated_at
		FROM assets a
		LEFT JOIN agents ag ON ag.id = a.agent_id
		LEFT JOIN asset_risk_scores rs ON rs.agent_id = a.agent_id
		WHERE a.id=$1 AND a.tenant_id=$2
	`, id, tenantID).Scan(
		&a.ID, &a.TenantID, &a.AgentID, &a.Name, &a.Hostname, &a.IPAddress,
		&a.AssetType, &a.Owner, &a.BusinessUnit, &a.Criticality,
		&a.DataClassification, &a.Environment, &a.Location,
		&tagsJSON, &a.Notes, &a.AgentStatus, &a.RiskScore,
		&a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return a, err
	}
	json.Unmarshal(tagsJSON, &a.Tags)
	if a.Tags == nil {
		a.Tags = []string{}
	}
	return a, nil
}

func UpdateAsset(a models.Asset) error {
	tags, _ := json.Marshal(a.Tags)
	_, err := database.DB.Exec(`
		UPDATE assets SET
		  name=$1, hostname=$2, ip_address=$3, asset_type=$4, owner=$5,
		  business_unit=$6, criticality=$7, data_classification=$8,
		  environment=$9, location=$10, tags=$11, notes=$12, updated_at=NOW()
		WHERE id=$13 AND tenant_id=$14
	`, a.Name, a.Hostname, a.IPAddress, a.AssetType, a.Owner,
		a.BusinessUnit, a.Criticality, a.DataClassification,
		a.Environment, a.Location, tags, a.Notes, a.ID, a.TenantID,
	)
	return err
}

func DeleteAsset(id, tenantID int) error {
	_, err := database.DB.Exec(`DELETE FROM assets WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

// EnsureAssetForAgent creates an asset record for an agent if none exists yet.
// Called on agent heartbeat so the CMDB is auto-populated.
func EnsureAssetForAgent(agentID, tenantID int, hostname, ip string) error {
	_, err := database.DB.Exec(`
		INSERT INTO assets (tenant_id, agent_id, name, hostname, ip_address, asset_type)
		VALUES ($1, $2, $3, $4, $5, 'server')
		ON CONFLICT (agent_id) DO NOTHING
	`, tenantID, agentID, hostname, hostname, ip)
	return err
}

func GetAssetCounts(tenantID int) (total, critical int) {
	database.DB.QueryRow(`SELECT COUNT(*) FROM assets WHERE tenant_id=$1`, tenantID).Scan(&total)
	database.DB.QueryRow(`SELECT COUNT(*) FROM assets WHERE tenant_id=$1 AND criticality='critical'`, tenantID).Scan(&critical)
	return
}

func scanAssets(rows interface {
	Next() bool
	Scan(...any) error
	Close() error
}) ([]models.Asset, error) {
	defer rows.Close()
	var out []models.Asset
	for rows.Next() {
		var a models.Asset
		var tagsJSON []byte
		if err := rows.Scan(
			&a.ID, &a.TenantID, &a.AgentID, &a.Name, &a.Hostname, &a.IPAddress,
			&a.AssetType, &a.Owner, &a.BusinessUnit, &a.Criticality,
			&a.DataClassification, &a.Environment, &a.Location,
			&tagsJSON, &a.Notes, &a.AgentStatus, &a.RiskScore,
			&a.CreatedAt, &a.UpdatedAt,
		); err == nil {
			json.Unmarshal(tagsJSON, &a.Tags)
			if a.Tags == nil {
				a.Tags = []string{}
			}
			out = append(out, a)
		}
	}
	return out, nil
}
