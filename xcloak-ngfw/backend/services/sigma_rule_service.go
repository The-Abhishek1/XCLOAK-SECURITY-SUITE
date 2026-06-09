package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func CreateSigmaRule(
	rule models.SigmaRule,
) error {

	return repositories.CreateSigmaRule(
		rule,
	)
}

func GetSigmaRules() (
	[]models.SigmaRule,
	error,
) {

	return repositories.GetRules()
}

func GetSigmaRuleByID(
	id string,
) (*models.SigmaRule, error) {

	return repositories.GetSigmaRuleByID(id)
}

func UpdateSigmaRule(
	id string,
	rule models.SigmaRule,
) error {

	return repositories.UpdateSigmaRule(
		id,
		rule,
	)
}

func DeleteSigmaRule(
	id string,
) error {

	return repositories.DeleteSigmaRule(id)
}

func EnableSigmaRule(
	id string,
) error {

	return repositories.EnableRule(
		id,
	)
}

func DisableSigmaRule(
	id string,
) error {

	return repositories.DisableRule(
		id,
	)
}

func GetEnabledSigmaRules() (
	[]models.SigmaRule,
	error,
) {

	return repositories.GetEnabledRules()
}
