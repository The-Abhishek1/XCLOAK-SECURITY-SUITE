package services

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf16"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// ─────────────────────────────────────────────────────────────────────────────
// EvaluateRules runs every enabled Sigma rule against an incoming log line.
// If parsed_fields JSON is present, field-level matching is used.
// Matches that pass logsource filtering are recorded as hits and fire alerts.
// ─────────────────────────────────────────────────────────────────────────────

func EvaluateRules(log models.Log) {
	rules, err := GetEnabledSigmaRulesForAgent(log.AgentID)
	if err != nil {
		return
	}

	messageLower := strings.ToLower(log.LogMessage)

	var pf ParsedFields
	if log.ParsedFields != "" && log.ParsedFields != "{}" {
		json.Unmarshal([]byte(log.ParsedFields), &pf)
	}

	for _, rule := range rules {
		if !ruleMatchesLogsource(rule, pf) {
			continue
		}
		if !matchSigmaRuleWithFields(rule, messageLower, pf) {
			continue
		}

		alert := models.Alert{
			AgentID:        log.AgentID,
			RuleName:       rule.Title,
			Severity:       rule.Severity,
			MitreTactic:    rule.MitreTactic,
			MitreTechnique: rule.MitreTechnique,
			MitreName:      rule.MitreName,
			Fingerprint: fmt.Sprintf("%d-%s", log.AgentID,
				strings.ReplaceAll(rule.Title, " ", "-")),
			LogMessage: log.LogMessage,
		}

		CreateAlert(alert)
		CorrelateAlert(alert)

		// Record the hit asynchronously — must not block the ingestion pipeline.
		go func(ruleID, agentID int) {
			tenantID, _ := repositories.GetTenantIDByAgentID(agentID)
			repositories.RecordSigmaHit(ruleID, agentID, tenantID)
		}(rule.ID, log.AgentID)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Logsource matching
// ─────────────────────────────────────────────────────────────────────────────

// ruleMatchesLogsource returns false only when the rule has an explicit product
// or service constraint that is incompatible with the log's parsed format.
func ruleMatchesLogsource(rule models.SigmaRule, pf ParsedFields) bool {
	if rule.LogsourceProduct == "" && rule.LogsourceCategory == "" && rule.LogsourceService == "" {
		return true // unconstrained — applies to everything
	}

	prod := strings.ToLower(rule.LogsourceProduct)
	svc := strings.ToLower(rule.LogsourceService)
	format := strings.ToLower(pf.Format)

	switch prod {
	case "windows":
		if format != "" && format != "winevent" {
			return false
		}
	case "linux", "unix":
		if format != "" && format != "syslog3164" && format != "syslog5424" && format != "raw" {
			return false
		}
	case "network":
		if format != "" && format != "cef" && format != "raw" {
			return false
		}
	}

	// Service-level filter: check process name
	if svc != "" && pf.Process != "" {
		if !strings.Contains(strings.ToLower(pf.Process), svc) {
			return false
		}
	}

	return true
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule matching
// ─────────────────────────────────────────────────────────────────────────────

func MatchSigmaRule(rule models.SigmaRule, messageLower string) bool {
	return matchSigmaRuleWithFields(rule, messageLower, ParsedFields{})
}

func matchSigmaRuleWithFields(rule models.SigmaRule, messageLower string, pf ParsedFields) bool {
	selections := rule.Selections
	if len(selections) == 0 {
		if len(rule.Keywords) == 0 {
			return false
		}
		selections = map[string][]string{"selection1": rule.Keywords}
	}

	results := make(map[string]bool, len(selections))

	for name, keywords := range selections {
		results[name] = evalSelection(keywords, messageLower, pf)
	}

	condition := rule.Condition
	if condition == "" && len(rule.Selections) == 0 {
		condition = "selection1"
	}

	return EvaluateCondition(condition, results)
}

// evalSelection evaluates a selection's keyword list against the log.
// If all keywords carry the "__ALL__" prefix the selection requires every
// keyword to match (AND); otherwise any match suffices (OR).
func evalSelection(keywords []string, messageLower string, pf ParsedFields) bool {
	if len(keywords) == 0 {
		return false
	}

	allRequired := strings.HasPrefix(keywords[0], "__ALL__")

	if allRequired {
		for _, kw := range keywords {
			kw = strings.TrimPrefix(kw, "__ALL__")
			if !matchKeyword(kw, messageLower, pf) {
				return false
			}
		}
		return true
	}

	for _, kw := range keywords {
		if matchKeyword(kw, messageLower, pf) {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// Keyword matching with full Sigma modifier chain support
//
// Keyword syntax: field|mod1|mod2:value   OR   plain keyword
//
// Transform modifiers (applied to value before comparison):
//   base64        — base64-encode the value
//   base64offset  — generate 3 base64 variants covering alignment offsets
//   windash       — expand to -, /, – (en-dash), — (em-dash) variants
//   utf16le       — encode value as UTF-16LE bytes (typically chained with base64)
//   utf16be       — encode value as UTF-16BE bytes
//
// Comparison modifiers:
//   contains      — substring match (case-insensitive)
//   startswith    — prefix match
//   endswith      — suffix match
//   re            — regex (case-sensitive; add (?i) for insensitivity)
//   cidr          — CIDR range (field must be an IP address)
//   lt / lte / gt / gte — numeric comparison
//   (default)     — exact match (case-insensitive)
// ─────────────────────────────────────────────────────────────────────────────

func matchKeyword(keyword, messageLower string, pf ParsedFields) bool {
	colonIdx := strings.Index(keyword, ":")
	if colonIdx <= 0 {
		// Plain keyword → substring match against full message.
		return strings.Contains(messageLower, strings.ToLower(keyword))
	}

	lhs := keyword[:colonIdx]
	rhsRaw := keyword[colonIdx+1:]

	// Split lhs into field name and modifier chain.
	parts := strings.Split(lhs, "|")
	fieldName := parts[0]
	modifiers := parts[1:]

	// Separate transform modifiers from the comparison modifier.
	var transforms []string
	comparison := "exact"
	for _, mod := range modifiers {
		switch strings.ToLower(mod) {
		case "base64", "base64offset", "windash", "utf16le", "utf16be":
			transforms = append(transforms, strings.ToLower(mod))
		case "contains", "startswith", "endswith", "re", "cidr",
			"lt", "lte", "gt", "gte":
			comparison = strings.ToLower(mod)
		case "all":
			// handled by __ALL__ prefix at import time
		}
	}

	fieldVal, exists := GetFieldValue(pf, strings.ToLower(fieldName))
	if !exists {
		// Field not in parsed fields — fall back to message-level match
		// only if the field name looks non-standard (contains spaces or is long).
		if strings.Contains(fieldName, " ") || len(fieldName) > 30 {
			return strings.Contains(messageLower, strings.ToLower(keyword))
		}
		return false
	}

	// Apply value transforms to generate the set of candidate values to match against.
	candidates := applyTransforms(rhsRaw, transforms)

	// For regex, don't lowercase.
	if comparison == "re" {
		re, err := compileSigmaRegex(rhsRaw)
		if err != nil {
			return false
		}
		return re.MatchString(fieldVal)
	}

	fvLower := strings.ToLower(fieldVal)

	for _, cand := range candidates {
		candLower := strings.ToLower(cand)
		switch comparison {
		case "exact":
			if fvLower == candLower {
				return true
			}
		case "contains":
			if strings.Contains(fvLower, candLower) {
				return true
			}
		case "startswith":
			if strings.HasPrefix(fvLower, candLower) {
				return true
			}
		case "endswith":
			if strings.HasSuffix(fvLower, candLower) {
				return true
			}
		case "cidr":
			_, network, err := net.ParseCIDR(cand)
			if err == nil {
				ip := net.ParseIP(fieldVal)
				if ip != nil && network.Contains(ip) {
					return true
				}
			}
		case "lt", "lte", "gt", "gte":
			f, err1 := strconv.ParseFloat(fieldVal, 64)
			v, err2 := strconv.ParseFloat(cand, 64)
			if err1 == nil && err2 == nil {
				switch comparison {
				case "lt":
					if f < v {
						return true
					}
				case "lte":
					if f <= v {
						return true
					}
				case "gt":
					if f > v {
						return true
					}
				case "gte":
					if f >= v {
						return true
					}
				}
			}
		}
	}
	return false
}

// applyTransforms applies a chain of transform modifiers to a raw value and
// returns all candidate values that should be tested against the field.
func applyTransforms(value string, transforms []string) []string {
	values := []string{value}
	for _, t := range transforms {
		var next []string
		switch t {
		case "base64":
			for _, v := range values {
				next = append(next, base64.StdEncoding.EncodeToString([]byte(v)))
			}
		case "base64offset":
			// Generate 3 variants to cover alignment at byte offsets 0, 1, 2.
			for _, v := range values {
				for _, pad := range []string{"", "A", "AA"} {
					padded := []byte(pad + v)
					encoded := base64.StdEncoding.EncodeToString(padded)
					// Strip the base64 chars that encode the padding prefix.
					skip := (len(pad) * 4) / 3
					if skip > 0 && skip < len(encoded) {
						encoded = encoded[skip:]
					}
					next = append(next, encoded)
				}
			}
		case "windash":
			for _, v := range values {
				next = append(next,
					v,
					strings.ReplaceAll(v, "-", "/"),
					strings.ReplaceAll(v, "-", "–"), // en-dash
					strings.ReplaceAll(v, "-", "—"), // em-dash
				)
			}
		case "utf16le":
			for _, v := range values {
				next = append(next, encodeUTF16(v, binary.LittleEndian))
			}
		case "utf16be":
			for _, v := range values {
				next = append(next, encodeUTF16(v, binary.BigEndian))
			}
		default:
			next = values
		}
		values = next
	}
	return values
}

// encodeUTF16 returns a string of the UTF-16 byte sequence of s.
func encodeUTF16(s string, order binary.ByteOrder) string {
	runes := utf16.Encode([]rune(s))
	buf := make([]byte, len(runes)*2)
	for i, r := range runes {
		order.PutUint16(buf[i*2:], r)
	}
	return string(buf)
}

var sigmaRegexCache sync.Map

func compileSigmaRegex(pattern string) (*regexp.Regexp, error) {
	if cached, ok := sigmaRegexCache.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	sigmaRegexCache.Store(pattern, re)
	return re, nil
}

// EvaluateCondition, tokenizeCondition, and the condition parser live in
// sigma_condition_parser.go.
