package services

import (
	"fmt"
	"net"
	"strings"
)

// ParseIPAllowlist parses a comma-separated list of CIDR blocks (e.g.
// "10.0.0.0/8, 192.168.0.0/16"). A bare IP without a "/prefix" is treated as
// a /32 (or /128 for IPv6) single-address block. An empty/blank string
// parses to an empty, non-restrictive list.
func ParseIPAllowlist(csv string) ([]*net.IPNet, error) {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil, nil
	}
	var nets []*net.IPNet
	for _, part := range strings.Split(csv, ",") {
		entry := strings.TrimSpace(part)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP or CIDR: %q", entry)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			entry = fmt.Sprintf("%s/%d", entry, bits)
		}
		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", entry, err)
		}
		nets = append(nets, ipNet)
	}
	return nets, nil
}

// IsIPAllowed reports whether clientIP is permitted by allowlist. An empty
// allowlist means "allow all" (the feature is off), matching the Settings
// UI's documented "empty = allow all" hint.
func IsIPAllowed(clientIP string, allowlist []*net.IPNet) bool {
	if len(allowlist) == 0 {
		return true
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	for _, n := range allowlist {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
