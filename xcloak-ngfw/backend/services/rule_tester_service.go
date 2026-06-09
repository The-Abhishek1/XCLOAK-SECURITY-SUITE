package services

import (
	"strings"

	"xcloak-ngfw/models"
)

func TestRules(
	message string,
) []models.RuleTestResult {

	rules, err := GetEnabledSigmaRules()

	if err != nil {
		return nil
	}

	var results []models.RuleTestResult

	message = strings.ToLower(
		message,
	)

	for _, rule := range rules {

		matched := false

		for _, keyword := range rule.Keywords {

			if strings.Contains(
				message,
				strings.ToLower(keyword),
			) {

				matched = true
				break
			}
		}

		results = append(
			results,
			models.RuleTestResult{
				RuleName: rule.Title,
				Matched:  matched,
			},
		)
	}

	return results
}
