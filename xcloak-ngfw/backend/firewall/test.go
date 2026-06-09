package firewall

import (
	"fmt"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func PrintRules() {

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
	`)

	if err != nil {
		fmt.Println(err)
		return
	}

	defer rows.Close()

	for rows.Next() {

		var rule models.FirewallRule

		rows.Scan(
			&rule.ID,
			&rule.Name,
			&rule.SourceIP,
			&rule.DestinationIP,
			&rule.Protocol,
			&rule.Port,
			&rule.Action,
			&rule.Enabled,
		)

		cmd := GenerateNFTCommand(rule)

		fmt.Println(cmd)
	}
}