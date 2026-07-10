package services

import (
	"testing"
)

func TestIPIOCMatches(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		indicator  string
		want       bool
	}{
		// Exact IP matches with port stripped
		{"exact ip with port", "1.2.3.4:443", "1.2.3.4", true},
		{"exact ip no port", "1.2.3.4", "1.2.3.4", true},
		{"different ip", "1.2.3.5:443", "1.2.3.4", false},

		// CIDR containment
		{"cidr contained", "192.168.1.50:80", "192.168.1.0/24", true},
		{"cidr not contained", "10.0.0.1:80", "192.168.1.0/24", false},
		{"cidr /32", "1.2.3.4:443", "1.2.3.4/32", true},
		{"cidr /32 miss", "1.2.3.5:443", "1.2.3.4/32", false},

		// Regression: old strings.Contains caused "1.2.3.4" to match "11.2.3.41"
		{"no substring match", "11.2.3.41:443", "1.2.3.4", false},
		{"no substring match reverse", "1.2.3.4:443", "11.2.3.41", false},

		// IPv6
		{"ipv6 exact bracketed", "[2001:db8::1]:443", "2001:db8::1", true},
		{"ipv6 cidr", "[2001:db8::1]:443", "2001:db8::/32", true},
		{"ipv6 cidr miss", "[2001:db8:1::1]:443", "2001:db8:2::/48", false},

		// Invalid inputs — must not panic
		{"invalid remote addr", "not-an-ip:443", "1.2.3.4", false},
		{"invalid indicator ip", "1.2.3.4:443", "not-an-ip", false},
		{"invalid cidr", "1.2.3.4:443", "1.2.3.4/999", false},
		{"empty remote", "", "1.2.3.4", false},
		{"empty indicator", "1.2.3.4:443", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ipIOCMatches(tc.remoteAddr, tc.indicator)
			if got != tc.want {
				t.Errorf("ipIOCMatches(%q, %q) = %v, want %v",
					tc.remoteAddr, tc.indicator, got, tc.want)
			}
		})
	}
}
