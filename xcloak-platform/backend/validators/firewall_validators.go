package validators

import (
	"errors"

	"xcloak-platform/models"
)

func ValidateFirewallRule(
	rule models.FirewallRule,
) error {

	if rule.Name == "" {
		return errors.New("name required")
	}

	if rule.Port < 1 || rule.Port > 65535 {
		return errors.New("invalid port")
	}

	return nil
}
