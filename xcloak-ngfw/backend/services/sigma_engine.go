package services

import (
	"encoding/json"
	"fmt"
	"strings"

	"xcloak-ngfw/models"
)

// ─────────────────────────────────────────────────────────────────────────────
// MatchSigmaRule evaluates a single Sigma-lite rule against a log entry.
//
// Detection model:
//   1. Field-level selections (new): each keyword in a selection can be
//      "field:value" for field-level matching, "field|contains:value" for
//      substring, or a plain keyword for message-level matching.
//   2. Legacy keyword-only rules are preserved with backward compatibility.
//
// Examples of field-level keywords (stored in rule.Selections):
//   "src_ip:10.0.0.1"         — exact match on src_ip field
//   "src_ip|contains:10.0"    — substring match
//   "event_id:4625"           — exact match on event_id
//   "user|contains:admin"     — substring
//   "auth_result:failure"     — exact
//   "Failed password"         — plain keyword → checked against log_message
// ─────────────────────────────────────────────────────────────────────────────

func MatchSigmaRule(rule models.SigmaRule, messageLower string) bool {
	return matchSigmaRuleWithFields(rule, messageLower, ParsedFields{})
}

// MatchSigmaRuleWithFields is the field-aware version used when parsed fields
// are available (called from EvaluateRules when log has ParsedFields JSON).
func matchSigmaRuleWithFields(rule models.SigmaRule, messageLower string, pf ParsedFields) bool {

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
			if matchKeyword(kw, messageLower, pf) {
				matched = true
				break
			}
		}
		results[name] = matched
	}

	condition := rule.Condition
	if condition == "" && len(rule.Selections) == 0 {
		condition = "selection1"
	}

	return EvaluateCondition(condition, results)
}

// matchKeyword matches a single keyword against the log.
//
// Syntax:
//   field:value           — exact match (case-insensitive) on named field
//   field|contains:value  — substring match on named field
//   field|startswith:value
//   field|endswith:value
//   field|re:pattern      — reserved for future regex support
//   plain text            — substring match against the full log message
func matchKeyword(keyword, messageLower string, pf ParsedFields) bool {

	// ── Field-level match: "field:value" or "field|op:value" ─────
	colonIdx := strings.Index(keyword, ":")
	if colonIdx > 0 {
		// Everything before the colon is "field" or "field|op".
		lhs := keyword[:colonIdx]
		rhs := strings.ToLower(keyword[colonIdx+1:])

		fieldName := lhs
		op        := "exact"

		if pipeIdx := strings.Index(lhs, "|"); pipeIdx >= 0 {
			fieldName = lhs[:pipeIdx]
			op        = strings.ToLower(lhs[pipeIdx+1:])
		}

		fieldVal, exists := GetFieldValue(pf, strings.ToLower(fieldName))
		if !exists {
			// Field not extracted — fall through to message-level check only
			// if the keyword doesn't look like a field expression.
			// A bare IP or word before ":" could be a timestamp or URL.
			// Heuristic: if fieldName contains spaces or is longer than 30
			// chars, it's not a field name.
			if strings.Contains(fieldName, " ") || len(fieldName) > 30 {
				return strings.Contains(messageLower, strings.ToLower(keyword))
			}
			return false
		}

		fieldValLower := strings.ToLower(fieldVal)

		switch op {
		case "contains":
			return strings.Contains(fieldValLower, rhs)
		case "startswith":
			return strings.HasPrefix(fieldValLower, rhs)
		case "endswith":
			return strings.HasSuffix(fieldValLower, rhs)
		default: // "exact" or unknown
			return fieldValLower == rhs
		}
	}

	// ── Plain keyword → message-level substring match ─────────────
	return strings.Contains(messageLower, strings.ToLower(keyword))
}

// ─────────────────────────────────────────────────────────────────────────────
// EvaluateRules runs every enabled Sigma rule against an incoming log line.
// If parsed_fields JSON is present on the log, field-level matching is used.
// ─────────────────────────────────────────────────────────────────────────────

func EvaluateRules(log models.Log) {

	rules, err := GetEnabledSigmaRules()
	if err != nil {
		return
	}

	messageLower := strings.ToLower(log.LogMessage)

	// Deserialise parsed fields if available.
	var pf ParsedFields
	if log.ParsedFields != "" && log.ParsedFields != "{}" {
		json.Unmarshal([]byte(log.ParsedFields), &pf)
	}

	for _, rule := range rules {

		if !matchSigmaRuleWithFields(rule, messageLower, pf) {
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
	}
}

// EvaluateCondition, tokenizeCondition, and the condition parser live in
// sigma_condition_parser.go.
