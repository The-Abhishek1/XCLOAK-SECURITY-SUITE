package services

import (
	"fmt"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/validators"
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
// returns any conflicts found. Only enabled rules are considered.
func DetectFirewallConflicts(tenantID int) ([]FirewallConflict, error) {
	rules, err := repositories.GetRulesForTenant(tenantID)
	if err != nil {
		return nil, err
	}

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
				conflicts = append(conflicts, FirewallConflict{
					Type:     "duplicate",
					Severity: "warning",
					Description: fmt.Sprintf(
						"Rule %q (priority %d) and %q (priority %d) match overlapping traffic and have the same action — one is redundant.",
						a.Name, a.Priority, b.Name, b.Priority,
					),
					RuleA: a.ID, RuleB: b.ID,
					RuleAName: a.Name, RuleBName: b.Name,
				})
			} else {
				conflicts = append(conflicts, FirewallConflict{
					Type:     "shadow",
					Severity: "error",
					Description: fmt.Sprintf(
						"Rule %q (priority %d, %s) shadows %q (priority %d, %s) — they match overlapping traffic but have opposing actions; %q will never be reached.",
						a.Name, a.Priority, a.Action, b.Name, b.Priority, b.Action, b.Name,
					),
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

// matchCriteria returns true if two rules cover overlapping traffic.
func matchCriteria(a, b models.FirewallRule) bool {
	return directionOverlaps(a.Direction, b.Direction) &&
		validators.CIDROverlaps(a.SourceIP, b.SourceIP) &&
		validators.CIDROverlaps(a.DestinationIP, b.DestinationIP) &&
		protoMatch(a.Protocol, b.Protocol) &&
		portRangesOverlap(a, b)
}

func directionOverlaps(a, b string) bool {
	if a == "" || a == "both" || b == "" || b == "both" {
		return true
	}
	return a == b
}

func protoMatch(x, y string) bool {
	if x == "any" || y == "any" || x == "" || y == "" {
		return true
	}
	return x == y
}

// portRangesOverlap checks whether the port specifications of two rules
// overlap. Handles: single port (Port field), comma-separated/range strings
// (PortRange field), and wildcard (port=0 or protocol=icmp/any).
func portRangesOverlap(a, b models.FirewallRule) bool {
	aRanges := effectivePortRanges(a)
	bRanges := effectivePortRanges(b)

	// nil means "any port" — always overlaps
	if aRanges == nil || bRanges == nil {
		return true
	}

	for _, ar := range aRanges {
		for _, br := range bRanges {
			if ar[0] <= br[1] && br[0] <= ar[1] {
				return true
			}
		}
	}
	return false
}

// effectivePortRanges returns nil (any port) or a list of [lo,hi] pairs.
func effectivePortRanges(r models.FirewallRule) [][2]int {
	proto := r.Protocol
	if proto == "icmp" || proto == "any" || proto == "" {
		return nil
	}
	if r.PortRange != "" {
		parsed := validators.ParsePortRange(r.PortRange)
		if len(parsed) == 0 {
			return nil
		}
		return parsed
	}
	if r.Port == 0 {
		return nil
	}
	return [][2]int{{r.Port, r.Port}}
}
