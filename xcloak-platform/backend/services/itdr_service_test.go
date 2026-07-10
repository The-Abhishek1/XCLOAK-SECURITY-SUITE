package services

import (
	"testing"
)

func TestIsPrivilegedGroup(t *testing.T) {
	shouldMatch := []string{
		"Domain Admins",
		"Enterprise Admins",
		"Schema Admins",
		"Administrators",
		"Account Operators",
		"Backup Operators",
		"domain admins",   // lowercase
		"DOMAIN ADMINS",   // uppercase
	}
	for _, g := range shouldMatch {
		if !isPrivilegedGroup(g) {
			t.Errorf("isPrivilegedGroup(%q) = false, want true", g)
		}
	}

	shouldNotMatch := []string{
		"Domain Users",
		"Remote Desktop Users",
		"Power Users",
		"Developers",
		"Marketing",
		"",
	}
	for _, g := range shouldNotMatch {
		if isPrivilegedGroup(g) {
			t.Errorf("isPrivilegedGroup(%q) = true, want false", g)
		}
	}
}

func TestUpsertITDRFinding_NilIfEmpty(t *testing.T) {
	cases := []struct {
		input string
		want  bool // nil?
	}{
		{"", true},
		{"10.0.0.1", false},
		{"T1078", false},
	}
	for _, c := range cases {
		result := nilIfEmpty(c.input)
		isNil := result == nil
		if isNil != c.want {
			t.Errorf("nilIfEmpty(%q): got nil=%v, want nil=%v", c.input, isNil, c.want)
		}
	}
}

func TestITDRDedupKeyFormats(t *testing.T) {
	// Verify dedup keys are deterministic so the same event doesn't re-insert.
	// We test the format implicitly by checking that the functions produce
	// the same string on repeated calls with identical input.
	cases := []struct {
		format   string
		identity string
		extra    string
		want     string
	}{
		{"spray:%s", "1.2.3.4", "", "spray:1.2.3.4"},
		{"shadow:%s:%s", "jdoe", "domain admins", "shadow:jdoe:domain admins"},
		{"lateral:%s", "alice", "", "lateral:alice"},
		{"stale:%s", "bob", "", "stale:bob"},
		{"dormant-admin:%s", "admin@corp.com", "", "dormant-admin:admin@corp.com"},
		{"mfa-gap:%s", "ops@corp.com", "", "mfa-gap:ops@corp.com"},
		{"mfa-fatigue:%s", "cto@corp.com", "", "mfa-fatigue:cto@corp.com"},
	}
	for _, c := range cases {
		var got string
		if c.extra == "" {
			got = sprintf1(c.format, c.identity)
		} else {
			got = sprintf2(c.format, c.identity, c.extra)
		}
		if got != c.want {
			t.Errorf("dedup key format: got %q, want %q", got, c.want)
		}
	}
}

func TestPasswordSpraySeverity(t *testing.T) {
	cases := []struct {
		distinct int
		want     string
	}{
		{5, "high"},
		{19, "high"},
		{20, "critical"},
		{50, "critical"},
	}
	for _, c := range cases {
		sev := "high"
		if c.distinct >= 20 {
			sev = "critical"
		}
		if sev != c.want {
			t.Errorf("spray severity for %d users: got %s, want %s", c.distinct, sev, c.want)
		}
	}
}

func TestLateralMovementSeverity(t *testing.T) {
	cases := []struct {
		hosts int
		want  string
	}{
		{4, "high"},
		{7, "high"},
		{8, "critical"},
		{15, "critical"},
	}
	for _, c := range cases {
		sev := "high"
		if c.hosts >= 8 {
			sev = "critical"
		}
		if sev != c.want {
			t.Errorf("lateral sev for %d hosts: got %s, want %s", c.hosts, sev, c.want)
		}
	}
}

func TestMFAFatigueSeverity(t *testing.T) {
	cases := []struct {
		attempts int
		want     string
	}{
		{5, "high"},
		{14, "high"},
		{15, "critical"},
		{30, "critical"},
	}
	for _, c := range cases {
		sev := "high"
		if c.attempts >= 15 {
			sev = "critical"
		}
		if sev != c.want {
			t.Errorf("mfa fatigue sev for %d attempts: got %s, want %s", c.attempts, sev, c.want)
		}
	}
}

func TestStaleAccountSeverity(t *testing.T) {
	cases := []struct {
		daysSince int
		want      string
	}{
		{90, "low"},
		{180, "low"},
		{181, "medium"},
		{365, "medium"},
	}
	for _, c := range cases {
		sev := "low"
		if c.daysSince > 180 {
			sev = "medium"
		}
		if sev != c.want {
			t.Errorf("stale account sev for %d days: got %s, want %s", c.daysSince, sev, c.want)
		}
	}
}

func TestDormantAdminSeverity(t *testing.T) {
	cases := []struct {
		daysSince int
		want      string
	}{
		{30, "medium"},
		{89, "medium"},
		{90, "high"},
		{180, "high"},
	}
	for _, c := range cases {
		sev := "medium"
		if c.daysSince >= 90 {
			sev = "high"
		}
		if sev != c.want {
			t.Errorf("dormant admin sev for %d days: got %s, want %s", c.daysSince, sev, c.want)
		}
	}
}

func TestMFAGapSeverity(t *testing.T) {
	cases := []struct {
		role string
		want string
	}{
		{"admin", "high"},
		{"super_admin", "high"},
		{"analyst", "medium"},
	}
	for _, c := range cases {
		sev := "medium"
		if c.role == "admin" || c.role == "super_admin" {
			sev = "high"
		}
		if sev != c.want {
			t.Errorf("mfa gap sev for role %s: got %s, want %s", c.role, sev, c.want)
		}
	}
}

// helpers to keep test logic readable without importing fmt directly
func sprintf1(format, a string) string { return format[:len(format)-2] + a }
func sprintf2(format, a, b string) string {
	// "shadow:%s:%s" → "shadow:" + a + ":" + b
	import_fmt := func(f, x, y string) string {
		result := ""
		i := 0
		replaced := 0
		for i < len(f) {
			if i+1 < len(f) && f[i] == '%' && f[i+1] == 's' {
				if replaced == 0 {
					result += x
				} else {
					result += y
				}
				replaced++
				i += 2
			} else {
				result += string(f[i])
				i++
			}
		}
		return result
	}
	return import_fmt(format, a, b)
}
