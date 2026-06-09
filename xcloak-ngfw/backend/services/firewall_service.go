package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
	"xcloak-ngfw/validators"
)

func CreateFirewallRule(
	rule models.FirewallRule,
) error {

	err := validators.ValidateFirewallRule(rule)

	if err != nil {
		return err
	}

	err = repositories.CreateRule(rule)

	if err != nil {
		return err
	}

	LogEvent(
		"CREATE_RULE",
		rule.Name,
		"system",
	)

	return nil
}
