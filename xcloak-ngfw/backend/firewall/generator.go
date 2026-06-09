package firewall

import (
	"fmt"

	"xcloak-ngfw/models"
)

func GenerateNFTCommand(rule models.FirewallRule) string {

	action := "drop"

	if rule.Action == "allow" {
		action = "accept"
	}

	cmd := fmt.Sprintf(
		"nft add rule inet xcloak test ip saddr %s %s dport %d %s",
		rule.SourceIP,
		rule.Protocol,
		rule.Port,
		action,
	)

	return cmd
}
