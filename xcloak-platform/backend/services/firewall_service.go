package services

import (
	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/validators"
)

func CreateFirewallRule(
	rule models.FirewallRule,
	tenantID int,
) error {

	err := validators.ValidateFirewallRule(rule)

	if err != nil {
		return err
	}

	err = repositories.CreateRule(rule, tenantID)

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
