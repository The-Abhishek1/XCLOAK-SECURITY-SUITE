package services

import (
	"strings"

	"xcloak-platform/models"
)

// TestRules runs every enabled Sigma rule against a sample log message using
// the SAME evaluation logic as live detection (MatchSigmaRule), so the
// "Test" button in the UI accurately reflects what would alert in production.
func TestRules(message string, tenantID int) []models.RuleTestResult {

	rules, err := GetEnabledSigmaRules(tenantID)
	if err != nil {
		return nil
	}

	messageLower := strings.ToLower(message)

	results := []models.RuleTestResult{}

	for _, rule := range rules {

		matched := MatchSigmaRule(rule, messageLower)

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
