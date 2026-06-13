package services

import (
	"fmt"
	"strings"

	"xcloak-ngfw/models"
)

// MatchSigmaRule evaluates a single Sigma-lite rule against a (lowercased)
// log message and returns whether it matches.
//
// Backward compatibility: if rule.Selections is empty, falls back to the
// old behavior — match if ANY keyword in rule.Keywords is present.
func MatchSigmaRule(rule models.SigmaRule, messageLower string) bool {

	selections := rule.Selections

	if len(selections) == 0 {
		if len(rule.Keywords) == 0 {
			return false
		}
		selections = map[string][]string{
			"selection1": rule.Keywords,
		}
	}

	results := make(map[string]bool, len(selections))

	for name, keywords := range selections {

		matched := false

		for _, kw := range keywords {

			kw = strings.TrimSpace(kw)
			if kw == "" {
				continue
			}

			if strings.Contains(messageLower, strings.ToLower(kw)) {
				matched = true
				break
			}
		}

		results[name] = matched
	}

	condition := rule.Condition
	if condition == "" && len(rule.Selections) == 0 {
		// Pure legacy rule with no condition — preserve "any keyword" semantics.
		condition = "selection1"
	}

	return EvaluateCondition(condition, results)
}

// EvaluateRules runs every enabled Sigma rule against an incoming log line.
// On a match, it creates an alert and runs correlation (which may, in turn,
// trigger SOAR playbooks).
func EvaluateRules(log models.Log) {

	rules, err := GetEnabledSigmaRules()
	if err != nil {
		return
	}

	messageLower := strings.ToLower(log.LogMessage)

	for _, rule := range rules {

		if !MatchSigmaRule(rule, messageLower) {
			continue
		}

		alert := models.Alert{
			AgentID: log.AgentID,

			RuleName: rule.Title,
			Severity: rule.Severity,

			MitreTactic:    rule.MitreTactic,
			MitreTechnique: rule.MitreTechnique,
			MitreName:      rule.MitreName,

			Fingerprint: fmt.Sprintf(
				"%d-%s",
				log.AgentID,
				strings.ReplaceAll(rule.Title, " ", "-"),
			),

			LogMessage: log.LogMessage,
		}

		CreateAlert(alert)
		CorrelateAlert(alert)

		// A rule firing once per log line is enough — move to the next rule.
	}
}
