package services

import (
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		// RFC1918 private ranges
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"192.168.255.255", true},

		// Loopback
		{"127.0.0.1", true},
		{"::1", true},

		// Special zero address
		{"0.0.0.0", true},

		// Public IPs — not private
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"172.64.0.1", false}, // public Cloudflare — NOT RFC1918
		{"203.0.113.1", false},

		// Invalid
		{"not-an-ip", false},
		{"", false},
		{"999.999.999.999", false},

		// IPv6 private / link-local
		{"fc00::1", true},
		{"fd00::1", true},
	}

	for _, tc := range tests {
		got := isPrivateIP(tc.ip)
		if got != tc.want {
			t.Errorf("isPrivateIP(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}
