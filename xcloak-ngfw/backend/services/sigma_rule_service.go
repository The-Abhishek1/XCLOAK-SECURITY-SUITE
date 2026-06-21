package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func CreateSigmaRule(
	rule models.SigmaRule,
	tenantID int,
) error {

	err := repositories.CreateSigmaRule(
		rule,
		tenantID,
	)
	if err == nil {
		InvalidateSigmaCache(tenantID)
	}
	return err
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

	err := repositories.UpdateSigmaRule(
		id,
		rule,
		tenantID,
	)
	if err == nil {
		InvalidateSigmaCache(tenantID)
	}
	return err
}

func DeleteSigmaRule(
	id string,
	tenantID int,
) error {

	err := repositories.DeleteSigmaRule(id, tenantID)
	if err == nil {
		InvalidateSigmaCache(tenantID)
	}
	return err
}

func EnableSigmaRule(
	id string,
	tenantID int,
) error {

	err := repositories.EnableRule(
		id,
		tenantID,
	)
	if err == nil {
		InvalidateSigmaCache(tenantID)
	}
	return err
}

func DisableSigmaRule(
	id string,
	tenantID int,
) error {

	err := repositories.DisableRule(
		id,
		tenantID,
	)
	if err == nil {
		InvalidateSigmaCache(tenantID)
	}
	return err
}

// GetEnabledSigmaRulesForAgent returns enabled rules for the tenant that
// owns agentID — used by the detection engine, which has no per-request
// tenant context of its own. Cached per-tenant (see sigma_cache.go) since
// this is called on every ingested log line.
func GetEnabledSigmaRulesForAgent(agentID int) (
	[]models.SigmaRule,
	error,
) {

	tenantID, err := repositories.GetTenantIDByAgentID(agentID)
	if err != nil {
		return nil, err
	}
	return getEnabledSigmaRulesCached(tenantID)
}

// GetEnabledSigmaRules returns enabled rules for tenantID — used by the rule
// tester, which has a real per-request tenant context from the caller's JWT.
func GetEnabledSigmaRules(tenantID int) (
	[]models.SigmaRule,
	error,
) {

	return getEnabledSigmaRulesCached(tenantID)
}
