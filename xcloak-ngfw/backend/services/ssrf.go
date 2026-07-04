package services

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// blockedCIDRs is the set of IP ranges that must not be reached by
// user-supplied webhook/integration URLs.
//
//   - 127.0.0.0/8  — loopback IPv4
//   - ::1/128       — loopback IPv6
//   - 10.0.0.0/8   — RFC 1918 private
//   - 172.16.0.0/12 — RFC 1918 private
//   - 192.168.0.0/16 — RFC 1918 private
//   - 169.254.0.0/16 — link-local (covers AWS/GCP/Azure metadata 169.254.169.254)
//   - fc00::/7      — unique-local IPv6
//   - fe80::/10     — link-local IPv6
//   - 0.0.0.0/8    — "this" network
var blockedCIDRs []*net.IPNet

func init() {
	prefixes := []string{
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
		"0.0.0.0/8",
		"100.64.0.0/10", // RFC 6598 shared address (carrier-grade NAT)
	}
	for _, p := range prefixes {
		_, cidr, err := net.ParseCIDR(p)
		if err == nil {
			blockedCIDRs = append(blockedCIDRs, cidr)
		}
	}
}

// blockedHostnames are exact hostnames that resolve to cloud metadata services.
// DNS names are checked before IP resolution so a metadata IP masquerading as
// a legit hostname is still caught by the CIDR check below.
var blockedHostnames = []string{
	"metadata.google.internal",
	"metadata.goog",
	"instance-data",
	"169.254.169.254",
}

// CheckURL validates that rawURL is safe to use as an outbound webhook target.
// It returns a non-nil error for:
//   - Non-HTTP/HTTPS schemes
//   - Hostnames that resolve to loopback, RFC1918, link-local, or metadata IPs
//   - Known cloud-metadata hostnames
//
// Use this before every outbound HTTP call driven by user-supplied URLs
// (integrations, playbook webhook actions, threat feed URLs, etc.).
func CheckURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("ssrf: invalid URL: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("ssrf: scheme %q not allowed (only http/https)", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("ssrf: missing host")
	}

	// Block known metadata hostnames before resolution.
	lower := strings.ToLower(host)
	for _, blocked := range blockedHostnames {
		if lower == blocked {
			return fmt.Errorf("ssrf: host %q is a blocked metadata endpoint", host)
		}
	}

	// Resolve hostname to IPs and check every address.
	addrs, err := net.LookupHost(host)
	if err != nil {
		// Unresolvable hosts are blocked — they may be internal names that
		// would resolve inside a private network but not from the internet.
		return fmt.Errorf("ssrf: cannot resolve host %q: %w", host, err)
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		for _, cidr := range blockedCIDRs {
			if cidr.Contains(ip) {
				return fmt.Errorf("ssrf: host %q resolves to blocked address %s (%s)", host, addr, cidr)
			}
		}
	}

	return nil
}
