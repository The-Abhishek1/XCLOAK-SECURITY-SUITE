package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func CreateRule(rule models.FirewallRule, tenantID int) error {
	if rule.Priority == 0 {
		rule.Priority = 100
	}
	_, err := database.DB.Exec(`
		INSERT INTO firewall_rules
		(name, source_ip, destination_ip, protocol, port, action, enabled, priority, tenant_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`,
		rule.Name, rule.SourceIP, rule.DestinationIP,
		rule.Protocol, rule.Port, rule.Action, rule.Enabled, rule.Priority, tenantID,
	)
	return err
}

// GetRulesForTenant returns firewall rules belonging to tenantID only. Use
// this from user-facing API paths and from the sync dispatcher, which must
// never push one tenant's rules onto another tenant's agents.
func GetRulesForTenant(tenantID int) ([]models.FirewallRule, error) {
	rows, err := database.DB.Query(`
		SELECT id, name, source_ip, destination_ip, protocol, port,
		       action, enabled,
		       COALESCE(priority, 100),
		       synced_at
		FROM firewall_rules
		WHERE tenant_id = $1
		ORDER BY COALESCE(priority, 100), id
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []models.FirewallRule
	for rows.Next() {
		var r models.FirewallRule
		if err := rows.Scan(
			&r.ID, &r.Name, &r.SourceIP, &r.DestinationIP,
			&r.Protocol, &r.Port, &r.Action, &r.Enabled,
			&r.Priority, &r.SyncedAt,
		); err == nil {
			rules = append(rules, r)
		}
	}
	return rules, nil
}

func GetRuleByID(id string, tenantID int) (*models.FirewallRule, error) {
	var r models.FirewallRule
	err := database.DB.QueryRow(`
		SELECT id, name, source_ip, destination_ip, protocol, port,
		       action, enabled,
		       COALESCE(priority, 100),
		       synced_at
		FROM firewall_rules WHERE id=$1 AND tenant_id=$2
	`, id, tenantID).Scan(
		&r.ID, &r.Name, &r.SourceIP, &r.DestinationIP,
		&r.Protocol, &r.Port, &r.Action, &r.Enabled,
		&r.Priority, &r.SyncedAt,
	)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func UpdateRule(id string, rule models.FirewallRule, tenantID int) (int64, error) {
	if rule.Priority == 0 {
		rule.Priority = 100
	}
	result, err := database.DB.Exec(`
		UPDATE firewall_rules
		SET name=$1, source_ip=$2, destination_ip=$3,
		    protocol=$4, port=$5, action=$6,
		    enabled=$7, priority=$8
		WHERE id=$9 AND tenant_id=$10
	`,
		rule.Name, rule.SourceIP, rule.DestinationIP,
		rule.Protocol, rule.Port, rule.Action,
		rule.Enabled, rule.Priority, id, tenantID,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func DeleteRule(id string, tenantID int) (int64, error) {
	result, err := database.DB.Exec(
		`DELETE FROM firewall_rules WHERE id=$1 AND tenant_id=$2`, id, tenantID,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
