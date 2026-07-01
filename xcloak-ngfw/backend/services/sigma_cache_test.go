package services

import (
	"testing"

	"xcloak-ngfw/models"
)

func sigmaRule(title, product string) models.SigmaRule {
	return models.SigmaRule{Title: title, LogsourceProduct: product, Severity: "medium"}
}

// testCacheEntry builds a cache entry with one rule per relevant product bucket
// plus two unconstrained rules.
func testCacheEntry() *sigmaCacheEntry {
	rules := []models.SigmaRule{
		sigmaRule("any1", ""),
		sigmaRule("any2", ""),
		sigmaRule("win1", "windows"),
		sigmaRule("lin1", "linux"),
		sigmaRule("unix1", "unix"),
		sigmaRule("net1", "network"),
	}
	return &sigmaCacheEntry{rules: rules, byProduct: buildProductIndex(rules)}
}

func titleSet(rules []models.SigmaRule) map[string]bool {
	out := make(map[string]bool, len(rules))
	for _, r := range rules {
		out[r.Title] = true
	}
	return out
}

// ── buildProductIndex ─────────────────────────────────────────────────────────

func TestBuildProductIndex_Buckets(t *testing.T) {
	rules := []models.SigmaRule{
		sigmaRule("win-a", "Windows"),
		sigmaRule("win-b", "windows"), // already lower-case
		sigmaRule("lin-a", "linux"),
		sigmaRule("net-a", "network"),
		sigmaRule("any-a", ""),
		sigmaRule("any-b", ""),
	}
	idx := buildProductIndex(rules)

	cases := []struct {
		bucket string
		want   int
	}{
		{"windows", 2}, // "Windows" and "windows" both fold to "windows"
		{"linux", 1},
		{"network", 1},
		{"", 2},
	}
	for _, tc := range cases {
		if got := len(idx[tc.bucket]); got != tc.want {
			t.Errorf("bucket %q: got %d rules, want %d", tc.bucket, got, tc.want)
		}
	}
}

func TestBuildProductIndex_EmptyInput(t *testing.T) {
	idx := buildProductIndex(nil)
	if len(idx) != 0 {
		t.Errorf("empty input: got non-empty index %v", idx)
	}
}

// ── getRulesForFormat ─────────────────────────────────────────────────────────

func TestGetRulesForFormat_Winevent(t *testing.T) {
	entry := testCacheEntry()
	got := titleSet(getRulesForFormat(entry, "winevent"))

	for _, want := range []string{"any1", "any2", "win1"} {
		if !got[want] {
			t.Errorf("winevent: expected rule %q", want)
		}
	}
	for _, notWant := range []string{"lin1", "unix1", "net1"} {
		if got[notWant] {
			t.Errorf("winevent: unexpected rule %q", notWant)
		}
	}
}

func TestGetRulesForFormat_Syslog3164(t *testing.T) {
	entry := testCacheEntry()
	got := titleSet(getRulesForFormat(entry, "syslog3164"))

	for _, want := range []string{"any1", "any2", "lin1", "unix1"} {
		if !got[want] {
			t.Errorf("syslog3164: expected rule %q", want)
		}
	}
	for _, notWant := range []string{"win1", "net1"} {
		if got[notWant] {
			t.Errorf("syslog3164: unexpected rule %q", notWant)
		}
	}
}

func TestGetRulesForFormat_Syslog5424(t *testing.T) {
	entry := testCacheEntry()
	got := titleSet(getRulesForFormat(entry, "syslog5424"))

	for _, want := range []string{"any1", "any2", "lin1", "unix1"} {
		if !got[want] {
			t.Errorf("syslog5424: expected rule %q", want)
		}
	}
	for _, notWant := range []string{"win1", "net1"} {
		if got[notWant] {
			t.Errorf("syslog5424: unexpected rule %q", notWant)
		}
	}
}

func TestGetRulesForFormat_CEF(t *testing.T) {
	entry := testCacheEntry()
	got := titleSet(getRulesForFormat(entry, "cef"))

	for _, want := range []string{"any1", "any2", "net1"} {
		if !got[want] {
			t.Errorf("cef: expected rule %q", want)
		}
	}
	for _, notWant := range []string{"win1", "lin1", "unix1"} {
		if got[notWant] {
			t.Errorf("cef: unexpected rule %q", notWant)
		}
	}
}

func TestGetRulesForFormat_Raw(t *testing.T) {
	entry := testCacheEntry()
	got := titleSet(getRulesForFormat(entry, "raw"))

	for _, want := range []string{"any1", "any2", "lin1", "unix1", "net1"} {
		if !got[want] {
			t.Errorf("raw: expected rule %q", want)
		}
	}
	if got["win1"] {
		t.Error("raw: unexpected windows rule in result")
	}
}

func TestGetRulesForFormat_UnknownReturnsAll(t *testing.T) {
	entry := testCacheEntry()
	// An unknown format must return the full rule list — can't eliminate anything.
	for _, format := range []string{"", "json", "csv", "UNKNOWN"} {
		got := getRulesForFormat(entry, format)
		if len(got) != len(entry.rules) {
			t.Errorf("format %q: got %d rules, want %d (all)", format, len(got), len(entry.rules))
		}
	}
}

func TestGetRulesForFormat_CaseInsensitive(t *testing.T) {
	entry := testCacheEntry()
	lower := titleSet(getRulesForFormat(entry, "winevent"))
	upper := titleSet(getRulesForFormat(entry, "WINEVENT"))
	mixed := titleSet(getRulesForFormat(entry, "WinEvent"))

	if len(lower) != len(upper) || len(lower) != len(mixed) {
		t.Errorf("format matching must be case-insensitive: lower=%d upper=%d mixed=%d",
			len(lower), len(upper), len(mixed))
	}
}

func TestGetRulesForFormat_OnlyUnconstrainedRules(t *testing.T) {
	// Tenant with only unconstrained rules — every format should still return them all.
	rules := []models.SigmaRule{
		sigmaRule("generic-a", ""),
		sigmaRule("generic-b", ""),
	}
	entry := &sigmaCacheEntry{rules: rules, byProduct: buildProductIndex(rules)}

	for _, format := range []string{"winevent", "syslog3164", "cef", "raw", ""} {
		got := getRulesForFormat(entry, format)
		if len(got) != 2 {
			t.Errorf("format %q with only unconstrained rules: got %d, want 2", format, len(got))
		}
	}
}
