package services

import (
	"testing"
)

func TestHostFromAddress(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		// Standard ip:port
		{"10.0.0.1:8080", "10.0.0.1"},
		{"192.168.1.1:443", "192.168.1.1"},
		{"1.2.3.4:22", "1.2.3.4"},

		// IPv6 bracketed
		{"[::1]:80", "::1"},
		{"[2001:db8::1]:443", "2001:db8::1"},

		// No port — returns as-is
		{"10.0.0.1", "10.0.0.1"},
		{"hostname", "hostname"},
		{"", ""},

		// Scope ID stripping (Linux ss output)
		{"192.168.1.1%eth0:68", "192.168.1.1"},
		{"fe80::1%lo:80", "fe80::1"},
	}

	for _, tc := range tests {
		got := hostFromAddress(tc.addr)
		if got != tc.want {
			t.Errorf("hostFromAddress(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

func TestIsListenPlaceholder(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		// Placeholders
		{"", true},
		{"0.0.0.0", true},
		{"::", true},
		{"127.0.0.1", true},
		{"::1", true},

		// Real addresses
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"8.8.8.8", false},
		{"2001:db8::1", false},

		// Unparseable — returns false
		{"not-an-ip", false},
	}

	for _, tc := range tests {
		got := isListenPlaceholder(tc.ip)
		if got != tc.want {
			t.Errorf("isListenPlaceholder(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}
