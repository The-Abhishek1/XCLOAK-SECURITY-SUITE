package services

import (
	"fmt"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// FirewallConflict describes a rule conflict or anomaly.
type FirewallConflict struct {
	Type        string `json:"type"`     // "duplicate" | "shadow" | "contradiction"
	Severity    string `json:"severity"` // "warning" | "error"
	Description string `json:"description"`
	RuleA       int    `json:"rule_a"`
	RuleB       int    `json:"rule_b"`
	RuleAName   string `json:"rule_a_name"`
	RuleBName   string `json:"rule_b_name"`
}

// DetectFirewallConflicts analyses the enabled ruleset for the tenant and
// returns any conflicts found. Only enabled rules are considered; disabled
// rules silently shadow nothing and conflict with nothing.
func DetectFirewallConflicts(tenantID int) ([]FirewallConflict, error) {
	rules, err := repositories.GetRulesForTenant(tenantID)
	if err != nil {
		return nil, err
	}

	// Only analyse enabled rules, ordered by priority (lower = higher precedence).
	var enabled []models.FirewallRule
	for _, r := range rules {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}

	var conflicts []FirewallConflict

	for i := 0; i < len(enabled); i++ {
		for j := i + 1; j < len(enabled); j++ {
			a, b := enabled[i], enabled[j]
			if !matchCriteria(a, b) {
				continue
			}

			if a.Action == b.Action {
				// Same criteria, same action → the later rule (b) is redundant.
				conflicts = append(conflicts, FirewallConflict{
					Type:        "duplicate",
					Severity:    "warning",
					Description: fmt.Sprintf("Rule %q (priority %d) and %q (priority %d) match identical traffic and have the same action — one is redundant.", a.Name, a.Priority, b.Name, b.Priority),
					RuleA: a.ID, RuleB: b.ID,
					RuleAName: a.Name, RuleBName: b.Name,
				})
			} else {
				// Same criteria, different action → higher-priority rule shadows lower.
				// Since enabled is ordered by priority ascending (lower number = higher
				// precedence), a always has equal-or-higher precedence than b.
				conflicts = append(conflicts, FirewallConflict{
					Type:        "shadow",
					Severity:    "error",
					Description: fmt.Sprintf("Rule %q (priority %d, action %s) shadows %q (priority %d, action %s) — they match the same traffic but have opposite actions; %q will never be reached.", a.Name, a.Priority, a.Action, b.Name, b.Priority, b.Action, b.Name),
					RuleA: a.ID, RuleB: b.ID,
					RuleAName: a.Name, RuleBName: b.Name,
				})
			}
		}
	}

	if conflicts == nil {
		conflicts = []FirewallConflict{}
	}
	return conflicts, nil
}

// matchCriteria returns true if two rules cover overlapping or identical
// traffic (same source IP / dest IP / protocol / port).
// Two rules "match" when all non-wildcard fields are equal.
func matchCriteria(a, b models.FirewallRule) bool {
	return ipMatch(a.SourceIP, b.SourceIP) &&
		ipMatch(a.DestinationIP, b.DestinationIP) &&
		protoMatch(a.Protocol, b.Protocol) &&
		portMatch(a.Port, b.Port, a.Protocol, b.Protocol)
}

func ipMatch(x, y string) bool {
	wildX := x == "" || x == "0.0.0.0/0" || x == "any"
	wildY := y == "" || y == "0.0.0.0/0" || y == "any"
	if wildX || wildY {
		return true // at least one is a wildcard — they overlap
	}
	return x == y
}

func protoMatch(x, y string) bool {
	if x == "any" || y == "any" || x == "" || y == "" {
		return true
	}
	return x == y
}

func portMatch(px, py int, px_proto, py_proto string) bool {
	// Port only matters for TCP/UDP.
	noPortX := px == 0 || px_proto == "icmp" || px_proto == "any"
	noPortY := py == 0 || py_proto == "icmp" || py_proto == "any"
	if noPortX || noPortY {
		return true
	}
	return px == py
}
