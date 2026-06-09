package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func CreateRule(rule models.FirewallRule) error {

	query := `
	INSERT INTO firewall_rules
	(name, source_ip, destination_ip, protocol, port, action, enabled)
	VALUES ($1,$2,$3,$4,$5,$6,$7)
	`

	_, err := database.DB.Exec(
		query,
		rule.Name,
		rule.SourceIP,
		rule.DestinationIP,
		rule.Protocol,
		rule.Port,
		rule.Action,
		rule.Enabled,
	)

	return err
}

func GetAllRules() ([]models.FirewallRule, error) {

	rows, err := database.DB.Query(`
	SELECT
		id,
		name,
		source_ip,
		destination_ip,
		protocol,
		port,
		action,
		enabled
	FROM firewall_rules
	ORDER BY id
	`)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var rules []models.FirewallRule

	for rows.Next() {

		var rule models.FirewallRule

		err := rows.Scan(
			&rule.ID,
			&rule.Name,
			&rule.SourceIP,
			&rule.DestinationIP,
			&rule.Protocol,
			&rule.Port,
			&rule.Action,
			&rule.Enabled,
		)

		if err != nil {
			continue
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

func GetRuleByID(id string) (*models.FirewallRule, error) {

	var rule models.FirewallRule

	query := `
	SELECT
		id,
		name,
		source_ip,
		destination_ip,
		protocol,
		port,
		action,
		enabled
	FROM firewall_rules
	WHERE id = $1
	`

	err := database.DB.QueryRow(
		query,
		id,
	).Scan(
		&rule.ID,
		&rule.Name,
		&rule.SourceIP,
		&rule.DestinationIP,
		&rule.Protocol,
		&rule.Port,
		&rule.Action,
		&rule.Enabled,
	)

	if err != nil {
		return nil, err
	}

	return &rule, nil
}

func UpdateRule(
	id string,
	rule models.FirewallRule,
) (int64, error) {

	query := `
	UPDATE firewall_rules
	SET
		name = $1,
		source_ip = $2,
		destination_ip = $3,
		protocol = $4,
		port = $5,
		action = $6,
		enabled = $7
	WHERE id = $8
	`

	result, err := database.DB.Exec(
		query,
		rule.Name,
		rule.SourceIP,
		rule.DestinationIP,
		rule.Protocol,
		rule.Port,
		rule.Action,
		rule.Enabled,
		id,
	)

	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

func DeleteRule(id string) (int64, error) {

	result, err := database.DB.Exec(
		"DELETE FROM firewall_rules WHERE id = $1",
		id,
	)

	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}
