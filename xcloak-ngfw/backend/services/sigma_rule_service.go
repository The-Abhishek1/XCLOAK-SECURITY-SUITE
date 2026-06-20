package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func CreateSigmaRule(
	rule models.SigmaRule,
	tenantID int,
) error {

	return repositories.CreateSigmaRule(
		rule,
		tenantID,
	)
}

func GetSigmaRules(tenantID int) (
	[]models.SigmaRule,
	error,
) {

	return repositories.GetRules(tenantID)
}

func GetSigmaRuleByID(
	id string,
	tenantID int,
) (*models.SigmaRule, error) {

	return repositories.GetSigmaRuleByID(id, tenantID)
}

func UpdateSigmaRule(
	id string,
	rule models.SigmaRule,
	tenantID int,
) error {

	return repositories.UpdateSigmaRule(
		id,
		rule,
		tenantID,
	)
}

func DeleteSigmaRule(
	id string,
	tenantID int,
) error {

	return repositories.DeleteSigmaRule(id, tenantID)
}

func EnableSigmaRule(
	id string,
	tenantID int,
) error {

	return repositories.EnableRule(
		id,
		tenantID,
	)
}

func DisableSigmaRule(
	id string,
	tenantID int,
) error {

	return repositories.DisableRule(
		id,
		tenantID,
	)
}

// GetEnabledSigmaRulesForAgent returns enabled rules for the tenant that
// owns agentID — used by the detection engine, which has no per-request
// tenant context of its own.
func GetEnabledSigmaRulesForAgent(agentID int) (
	[]models.SigmaRule,
	error,
) {

	return repositories.GetEnabledRulesForAgent(agentID)
}

// GetEnabledSigmaRules returns enabled rules for tenantID — used by the rule
// tester, which has a real per-request tenant context from the caller's JWT.
func GetEnabledSigmaRules(tenantID int) (
	[]models.SigmaRule,
	error,
) {

	return repositories.GetEnabledRules(tenantID)
}
