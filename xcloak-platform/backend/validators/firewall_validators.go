package validators

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"xcloak-platform/models"
)

var validDirections = map[string]bool{"in": true, "out": true, "both": true}
var validActions = map[string]bool{"allow": true, "deny": true, "drop": true, "reject": true, "log": true}

func ValidateFirewallRule(rule models.FirewallRule) error {
	if rule.Name == "" {
		return errors.New("name required")
	}
	if rule.Action == "" {
		return errors.New("action required")
	}
	if !validActions[strings.ToLower(rule.Action)] {
		return fmt.Errorf("invalid action %q — must be one of: allow, deny, drop, reject, log", rule.Action)
	}

	if rule.Direction != "" && !validDirections[strings.ToLower(rule.Direction)] {
		return fmt.Errorf("invalid direction %q — must be in, out, or both", rule.Direction)
	}

	if rule.SourceIP != "" && !isWildcard(rule.SourceIP) {
		if err := validateCIDROrIP(rule.SourceIP); err != nil {
			return fmt.Errorf("source_ip: %w", err)
		}
	}
	if rule.DestinationIP != "" && !isWildcard(rule.DestinationIP) {
		if err := validateCIDROrIP(rule.DestinationIP); err != nil {
			return fmt.Errorf("destination_ip: %w", err)
		}
	}

	if rule.Port != 0 {
		if rule.Port < 1 || rule.Port > 65535 {
			return errors.New("port must be between 1 and 65535")
		}
	}
	if rule.PortRange != "" {
		if err := ValidatePortRange(rule.PortRange); err != nil {
			return fmt.Errorf("port_range: %w", err)
		}
	}

	return nil
}

// ValidatePortRange accepts: "80", "443", "8000-9000", "80,443,8080", "8000-9000,443"
func ValidatePortRange(s string) error {
	segments := strings.Split(s, ",")
	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		if strings.Contains(seg, "-") {
			parts := strings.SplitN(seg, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil {
				return fmt.Errorf("invalid port range segment %q", seg)
			}
			if lo < 1 || hi > 65535 || lo > hi {
				return fmt.Errorf("port range %d-%d is out of bounds or reversed", lo, hi)
			}
		} else {
			p, err := strconv.Atoi(seg)
			if err != nil {
				return fmt.Errorf("invalid port %q", seg)
			}
			if p < 1 || p > 65535 {
				return fmt.Errorf("port %d out of range", p)
			}
		}
	}
	return nil
}

// ParsePortRange parses a port range string into a list of (lo, hi) pairs.
func ParsePortRange(s string) [][2]int {
	var out [][2]int
	for _, seg := range strings.Split(s, ",") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if strings.Contains(seg, "-") {
			parts := strings.SplitN(seg, "-", 2)
			lo, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
			hi, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
			out = append(out, [2]int{lo, hi})
		} else {
			p, _ := strconv.Atoi(seg)
			out = append(out, [2]int{p, p})
		}
	}
	return out
}

// CIDROverlaps returns true if the two CIDR strings overlap.
func CIDROverlaps(a, b string) bool {
	if isWildcard(a) || isWildcard(b) {
		return true
	}
	_, netA, errA := net.ParseCIDR(normalizeCIDR(a))
	_, netB, errB := net.ParseCIDR(normalizeCIDR(b))
	if errA != nil || errB != nil {
		return a == b
	}
	return netA.Contains(netB.IP) || netB.Contains(netA.IP)
}

func isWildcard(ip string) bool {
	return ip == "" || ip == "any" || ip == "0.0.0.0/0" || ip == "::/0"
}

func normalizeCIDR(s string) string {
	if !strings.Contains(s, "/") {
		// Bare IP — wrap in host CIDR.
		if strings.Contains(s, ":") {
			return s + "/128"
		}
		return s + "/32"
	}
	return s
}

func validateCIDROrIP(s string) error {
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		if err != nil {
			return fmt.Errorf("%q is not a valid CIDR", s)
		}
		return nil
	}
	if net.ParseIP(s) == nil {
		return fmt.Errorf("%q is not a valid IP address or CIDR", s)
	}
	return nil
}
