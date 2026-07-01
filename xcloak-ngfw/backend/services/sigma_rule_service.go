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

// GetEnabledSigmaRules returns enabled rules for tenantID — used by the rule
// tester, which has a real per-request tenant context from the caller's JWT.
func GetEnabledSigmaRules(tenantID int) (
	[]models.SigmaRule,
	error,
) {

	return getEnabledSigmaRulesCached(tenantID)
}

// GetSigmaStats returns per-rule hit counts and last-matched time for tenantID.
func GetSigmaStats(tenantID int) ([]repositories.SigmaRuleStat, error) {
	return repositories.GetSigmaStats(tenantID)
}
