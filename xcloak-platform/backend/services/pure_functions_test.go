package services

import (
	"encoding/json"
	"strings"
	"testing"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// ── ssnIsValid ─────────────────────────────────────────────────────────────────

func TestSSNIsValid(t *testing.T) {
	tests := []struct {
		ssn  string
		want bool
	}{
		{"123-45-6789", true},
		{"987-65-4321", false}, // area starts with 9 → ITIN
		{"000-45-6789", false}, // area 000
		{"666-45-6789", false}, // area 666
		{"123-00-6789", false}, // group 00
		{"123-45-0000", false}, // serial 0000
		{"12-45-6789", false},  // too short (len < 11)
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.ssn, func(t *testing.T) {
			got := ssnIsValid(tc.ssn)
			if got != tc.want {
				t.Errorf("ssnIsValid(%q) = %v, want %v", tc.ssn, got, tc.want)
			}
		})
	}
}

// ── ClassifyAssetType ─────────────────────────────────────────────────────────

func TestClassifyAssetType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"web_server", "web"},
		{"web_application", "web"},
		{"WEB", "web"},
		{"network_device", "network"},
		{"firewall", "network"},
		{"router", "network"},
		{"switch", "network"},
		{"load_balancer", "network"},
		{"cloud_instance", "cloud"},
		{"container", "cloud"},
		{"serverless", "cloud"},
		{"iot_device", "iot"},
		{"embedded", "iot"},
		{"mobile_ios", "ios"},
		{"ios", "ios"},
		{"mobile_android", "android"},
		{"android", "android"},
		{"database", "other"},
		{"", "other"},
		{"  Web_Server  ", "web"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := ClassifyAssetType(tc.input)
			if got != tc.want {
				t.Errorf("ClassifyAssetType(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ── truncate ──────────────────────────────────────────────────────────────────

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("truncate short string: got %q, want %q", got, "hello")
	}
	if got := truncate("hello world", 5); !strings.HasPrefix(got, "hello") {
		t.Errorf("truncate long string should start with 'hello', got %q", got)
	}
	if got := truncate("", 5); got != "" {
		t.Errorf("truncate empty string: got %q", got)
	}
	if got := truncate("hello", 5); got != "hello" {
		t.Errorf("truncate exact length: got %q, want %q", got, "hello")
	}
	long := truncate("abcdefghijklm", 5)
	if len(long) <= 5 {
		// Contains ellipsis: "abcde…" — byte length > 5 but visual is correct.
		if !strings.Contains(long, "abcde") {
			t.Errorf("truncate prefix wrong: %q", long)
		}
	}
}

// ── renderTemplate ────────────────────────────────────────────────────────────

func TestRenderTemplate(t *testing.T) {
	ctx := map[string]string{
		"severity":  "high",
		"rule_name": "Brute Force",
	}
	s := "Alert {{alert.severity}}: {{alert.rule_name}} detected"
	got := renderTemplate(s, ctx)
	want := "Alert high: Brute Force detected"
	if got != want {
		t.Errorf("renderTemplate = %q, want %q", got, want)
	}
}

func TestRenderTemplate_NoPlaceholders(t *testing.T) {
	s := "no placeholders here"
	got := renderTemplate(s, map[string]string{"key": "val"})
	if got != s {
		t.Errorf("renderTemplate with no placeholders: got %q, want %q", got, s)
	}
}

func TestRenderTemplate_UnknownKey(t *testing.T) {
	s := "{{alert.unknown}}"
	got := renderTemplate(s, map[string]string{"known": "val"})
	// Unrecognized placeholder left as-is.
	if got != s {
		t.Errorf("renderTemplate unknown key: got %q, want original %q", got, s)
	}
}

// ── renderPayload ─────────────────────────────────────────────────────────────

func TestRenderPayload_Substitutes(t *testing.T) {
	payload := json.RawMessage(`{"severity":"{{alert.severity}}"}`)
	ctx := map[string]string{"severity": "critical"}
	got := renderPayload(payload, ctx)
	if !strings.Contains(string(got), "critical") {
		t.Errorf("renderPayload: got %s, want 'critical' substituted", got)
	}
}

func TestRenderPayload_EmptyPayload(t *testing.T) {
	got := renderPayload(json.RawMessage{}, map[string]string{"k": "v"})
	if len(got) != 0 {
		t.Errorf("renderPayload empty: got %q, want empty", got)
	}
}

// ── globMatch ─────────────────────────────────────────────────────────────────

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    bool
	}{
		// No wildcard — exact match
		{"selection", "selection", true},
		{"selection", "other", false},
		// Trailing wildcard
		{"selection1", "selection*", true},
		{"selection_a", "selection*", true},
		{"other", "selection*", false},
		// Leading wildcard
		{"myselection", "*selection", true},
		{"my_other", "*selection", false},
		// Middle wildcard
		{"abc_xyz", "abc*xyz", true},
		{"abcxyz", "abc*xyz", true},
		{"abc", "abc*xyz", false},
		// Multiple wildcards
		{"a_b_c", "a*b*c", true},
		{"axbxc", "a*b*c", true},
		{"axc", "a*b*c", false},
		// Empty pattern
		{"", "", true},
		{"a", "", false},
		// Wildcard-only
		{"anything", "*", true},
		{"", "*", true},
	}
	for _, tc := range tests {
		t.Run(tc.name+"/"+tc.pattern, func(t *testing.T) {
			got := globMatch(tc.name, tc.pattern)
			if got != tc.want {
				t.Errorf("globMatch(%q, %q) = %v, want %v", tc.name, tc.pattern, got, tc.want)
			}
		})
	}
}

// ── applyTransforms ───────────────────────────────────────────────────────────

func TestApplyTransforms_NoTransforms(t *testing.T) {
	got := applyTransforms("hello", nil)
	if len(got) != 1 || got[0] != "hello" {
		t.Errorf("applyTransforms no transforms: got %v, want [hello]", got)
	}
}

func TestApplyTransforms_Base64(t *testing.T) {
	got := applyTransforms("cmd", []string{"base64"})
	if len(got) != 1 {
		t.Fatalf("applyTransforms base64: got %d values, want 1", len(got))
	}
	if got[0] == "cmd" {
		t.Error("base64 transform should change the value")
	}
}

func TestApplyTransforms_Base64Offset(t *testing.T) {
	got := applyTransforms("cmd", []string{"base64offset"})
	// Should produce 3 variants (offsets 0, 1, 2).
	if len(got) != 3 {
		t.Errorf("base64offset: got %d variants, want 3", len(got))
	}
}

func TestApplyTransforms_Windash(t *testing.T) {
	got := applyTransforms("-v", []string{"windash"})
	// Should produce 4 variants: original + /, en-dash, em-dash
	if len(got) != 4 {
		t.Errorf("windash: got %d variants, want 4", len(got))
	}
	found := false
	for _, v := range got {
		if v == "/v" {
			found = true
		}
	}
	if !found {
		t.Error("windash: /v variant not found")
	}
}

func TestApplyTransforms_UTF16LE(t *testing.T) {
	got := applyTransforms("A", []string{"utf16le"})
	if len(got) != 1 || got[0] == "A" {
		t.Errorf("utf16le transform should produce different value, got %v", got)
	}
}

func TestApplyTransforms_UTF16BE(t *testing.T) {
	got := applyTransforms("A", []string{"utf16be"})
	if len(got) != 1 || got[0] == "A" {
		t.Errorf("utf16be transform should produce different value, got %v", got)
	}
}

func TestApplyTransforms_Unknown(t *testing.T) {
	got := applyTransforms("hello", []string{"unknown_transform"})
	if len(got) != 1 || got[0] != "hello" {
		t.Errorf("unknown transform should be no-op, got %v", got)
	}
}

// ── matchKeyword ──────────────────────────────────────────────────────────────

func TestMatchKeyword_PlainSubstring(t *testing.T) {
	pf := ParsedFields{}
	if !matchKeyword("powershell", "running powershell.exe -enc abc", pf) {
		t.Error("plain keyword substring match failed")
	}
	if matchKeyword("notpresent", "running powershell.exe -enc abc", pf) {
		t.Error("plain keyword should not match when absent")
	}
}

func TestMatchKeyword_FieldExact(t *testing.T) {
	pf := ParsedFields{User: "alice"}
	if !matchKeyword("user:alice", "some msg alice", pf) {
		t.Error("user:alice exact match should succeed")
	}
	if matchKeyword("user:bob", "some msg alice", pf) {
		t.Error("user:bob should not match user=alice")
	}
}

func TestMatchKeyword_FieldContains(t *testing.T) {
	pf := ParsedFields{CommandLine: "cmd.exe /c whoami"}
	if !matchKeyword("commandline|contains:whoami", "some msg", pf) {
		t.Error("contains modifier match failed")
	}
	if matchKeyword("commandline|contains:nothere", "some msg", pf) {
		t.Error("contains modifier should not match absent value")
	}
}

func TestMatchKeyword_FieldStartsWith(t *testing.T) {
	pf := ParsedFields{CommandLine: "cmd.exe /c whoami"}
	if !matchKeyword("commandline|startswith:cmd.exe", "msg", pf) {
		t.Error("startswith modifier match failed")
	}
}

func TestMatchKeyword_FieldEndsWith(t *testing.T) {
	pf := ParsedFields{CommandLine: "cmd.exe /c whoami"}
	if !matchKeyword("commandline|endswith:whoami", "msg", pf) {
		t.Error("endswith modifier match failed")
	}
}

func TestMatchKeyword_FieldRegex(t *testing.T) {
	pf := ParsedFields{CommandLine: "cmd.exe /c whoami"}
	if !matchKeyword("commandline|re:^cmd\\.exe", "msg", pf) {
		t.Error("regex modifier match failed")
	}
}

func TestMatchKeyword_FieldRegexInvalid(t *testing.T) {
	pf := ParsedFields{CommandLine: "cmd.exe"}
	// Invalid regex — should return false, not panic.
	if matchKeyword("commandline|re:[invalid", "msg", pf) {
		t.Error("invalid regex should return false")
	}
}

func TestMatchKeyword_FieldNotFound_FallbackLongName(t *testing.T) {
	pf := ParsedFields{}
	// Field with spaces → falls back to message substring check.
	if !matchKeyword("some long field name:keyword", "some long field name:keyword in message", pf) {
		t.Error("long field name should fall back to message substring match")
	}
}

func TestMatchKeyword_FieldNotFound_ShortName(t *testing.T) {
	pf := ParsedFields{} // user is not set
	// Field "user" not in ParsedFields — returns false (no fallback for standard fields).
	if matchKeyword("user:alice", "user:alice in message", pf) {
		t.Error("missing short field name should not fall back to message match")
	}
}

// ── computeConfidence ─────────────────────────────────────────────────────────

func TestComputeConfidence_EventCountExtra(t *testing.T) {
	rule := repositories.EnabledCorrelationRule{CorrelationType: "event_count"}
	// signal=10 → 40+50=90 capped at 80
	if got := computeConfidence(rule, 10); got != 80 {
		t.Errorf("event_count signal=10: got %d, want 80 (capped)", got)
	}
}

func TestComputeConfidence_TemporalExtra(t *testing.T) {
	rule := repositories.EnabledCorrelationRule{CorrelationType: "temporal"}
	got := computeConfidence(rule, 3)
	if got < 30 || got > 95 {
		t.Errorf("temporal: confidence %d out of expected [30,95]", got)
	}
}

func TestComputeConfidence_SimpleDefault(t *testing.T) {
	// Default (empty CorrelationType) falls into the default branch.
	rule := repositories.EnabledCorrelationRule{}
	got := computeConfidence(rule, 0)
	if got < 40 || got > 95 {
		t.Errorf("default type: confidence %d out of expected [40,95]", got)
	}
}

// ── correlationRuleMatches helpers ───────────────────────────────────────────

func makeTestAlert(severity, ruleName string) models.Alert {
	return models.Alert{Severity: severity, RuleName: ruleName}
}

// ── correlationRuleMatches ────────────────────────────────────────────────────

func TestCorrelationRuleMatches_SeverityMismatch(t *testing.T) {
	rule := repositories.EnabledCorrelationRule{Severity: "high"}
	alert := makeTestAlert("low", "")
	if correlationRuleMatches(rule, alert) {
		t.Error("severity mismatch should not match")
	}
}

func TestCorrelationRuleMatches_SeverityMatch(t *testing.T) {
	rule := repositories.EnabledCorrelationRule{Severity: "high"}
	alert := makeTestAlert("HIGH", "")
	if !correlationRuleMatches(rule, alert) {
		t.Error("case-insensitive severity should match")
	}
}

func TestCorrelationRuleMatches_RuleNameMismatch(t *testing.T) {
	rule := repositories.EnabledCorrelationRule{RuleName: "bruteforce"}
	alert := makeTestAlert("high", "unrelated")
	if correlationRuleMatches(rule, alert) {
		t.Error("rule name mismatch should not match")
	}
}

func TestCorrelationRuleMatches_RuleNameSubstringExtra(t *testing.T) {
	rule := repositories.EnabledCorrelationRule{RuleName: "brute"}
	alert := makeTestAlert("high", "SSH Brute Force Detection")
	if !correlationRuleMatches(rule, alert) {
		t.Error("rule name substring should match (case-insensitive)")
	}
}

func TestCorrelationRuleMatches_AgentIDMismatch(t *testing.T) {
	rule := repositories.EnabledCorrelationRule{AgentID: 42}
	alert := makeTestAlert("high", "test")
	alert.AgentID = 99
	if correlationRuleMatches(rule, alert) {
		t.Error("agent ID mismatch should not match")
	}
}

func TestCorrelationRuleMatches_MitreMismatch(t *testing.T) {
	rule := repositories.EnabledCorrelationRule{MitreTechnique: "T1078"}
	alert := makeTestAlert("high", "test")
	alert.MitreTechnique = "T1110"
	if correlationRuleMatches(rule, alert) {
		t.Error("mitre technique mismatch should not match")
	}
}

func TestCorrelationRuleMatches_AllEmpty(t *testing.T) {
	rule := repositories.EnabledCorrelationRule{}
	alert := makeTestAlert("low", "anything")
	if !correlationRuleMatches(rule, alert) {
		t.Error("empty rule should match any alert")
	}
}

// ── parseHTTPAccessLog ────────────────────────────────────────────────────────

func TestParseHTTPAccessLog_CommonLogFormat(t *testing.T) {
	msg := `192.168.1.1 - alice [01/Jan/2025:00:00:00 +0000] "GET /admin HTTP/1.1" 200 1234`
	f := parseHTTPAccessLog(msg)
	if f == nil {
		t.Fatal("parseHTTPAccessLog returned nil for valid CLF line")
	}
	if f.SrcIP != "192.168.1.1" {
		t.Errorf("SrcIP = %q, want 192.168.1.1", f.SrcIP)
	}
	if f.HTTPMethod != "GET" {
		t.Errorf("HTTPMethod = %q, want GET", f.HTTPMethod)
	}
	if f.URLPath != "/admin" {
		t.Errorf("URLPath = %q, want /admin", f.URLPath)
	}
	if f.HTTPStatus != "200" {
		t.Errorf("HTTPStatus = %q, want 200", f.HTTPStatus)
	}
}

func TestParseHTTPAccessLog_Empty(t *testing.T) {
	f := parseHTTPAccessLog("") // must not panic, returns nil
	if f != nil {
		t.Errorf("parseHTTPAccessLog empty: expected nil, got %+v", f)
	}
}

// ── firstNonEmpty ─────────────────────────────────────────────────────────────

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "b", "c"); got != "b" {
		t.Errorf("firstNonEmpty = %q, want b", got)
	}
	if got := firstNonEmpty("a", "b"); got != "a" {
		t.Errorf("firstNonEmpty = %q, want a", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Errorf("firstNonEmpty all empty = %q, want empty", got)
	}
	if got := firstNonEmpty(); got != "" {
		t.Errorf("firstNonEmpty no args = %q, want empty", got)
	}
}
