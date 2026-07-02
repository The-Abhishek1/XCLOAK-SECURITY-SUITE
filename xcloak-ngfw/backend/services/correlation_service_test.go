package services

import (
	"testing"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// ── shouldCreateIncident ──────────────────────────────────────────────────────

func TestShouldCreateIncident(t *testing.T) {
	tests := []struct {
		name     string
		alert    models.Alert
		want     bool
	}{
		{"critical — always create", models.Alert{Severity: "critical", RuleName: "Any Rule"}, true},
		{"Critical uppercase — case insensitive", models.Alert{Severity: "Critical", RuleName: "Any Rule"}, true},
		{"high — always create", models.Alert{Severity: "high", RuleName: "Any Rule"}, true},
		{"medium — no auto-incident", models.Alert{Severity: "medium", RuleName: "Any Rule"}, false},
		{"low — no auto-incident", models.Alert{Severity: "low", RuleName: "Any Rule"}, false},
		{"ioc match — always create", models.Alert{Severity: "low", RuleName: "IOC Match"}, true},
		{"ioc match case insensitive", models.Alert{Severity: "low", RuleName: "Ioc Match"}, true},
		{"yara match — always create", models.Alert{Severity: "low", RuleName: "YARA Match"}, true},
		{"yara match case insensitive", models.Alert{Severity: "info", RuleName: "yara match"}, true},
		{"other low-sev rule — no incident", models.Alert{Severity: "info", RuleName: "Port Scan"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldCreateIncident(tc.alert)
			if got != tc.want {
				t.Errorf("shouldCreateIncident(%+v) = %v, want %v", tc.alert, got, tc.want)
			}
		})
	}
}

// ── correlationRuleMatches ────────────────────────────────────────────────────

func makeAlert(severity, ruleName, mitre string, agentID int) models.Alert {
	return models.Alert{
		Severity:       severity,
		RuleName:       ruleName,
		MitreTechnique: mitre,
		AgentID:        agentID,
	}
}

func makeRule(severity, ruleName, mitre string, agentID int) repositories.EnabledCorrelationRule {
	return repositories.EnabledCorrelationRule{
		Severity:       severity,
		RuleName:       ruleName,
		MitreTechnique: mitre,
		AgentID:        agentID,
	}
}

func TestCorrelationRuleMatches_BlankConditions(t *testing.T) {
	// Blank conditions match everything
	rule := makeRule("", "", "", 0)
	alert := makeAlert("low", "Irrelevant", "T9999", 42)
	if !correlationRuleMatches(rule, alert) {
		t.Error("blank rule should match any alert")
	}
}

func TestCorrelationRuleMatches_SeverityFilter(t *testing.T) {
	rule := makeRule("critical", "", "", 0)
	if correlationRuleMatches(rule, makeAlert("high", "", "", 1)) {
		t.Error("severity=critical rule must not match high alert")
	}
	if !correlationRuleMatches(rule, makeAlert("critical", "", "", 1)) {
		t.Error("severity=critical rule must match critical alert")
	}
	// Case insensitive
	if !correlationRuleMatches(rule, makeAlert("CRITICAL", "", "", 1)) {
		t.Error("severity match must be case-insensitive")
	}
}

func TestCorrelationRuleMatches_RuleNameSubstring(t *testing.T) {
	rule := makeRule("", "brute force", "", 0)
	if !correlationRuleMatches(rule, makeAlert("high", "SSH Brute Force Login", "", 1)) {
		t.Error("rule_name is a substring match — should match")
	}
	if correlationRuleMatches(rule, makeAlert("high", "Port Scan", "", 1)) {
		t.Error("rule_name substring must not match unrelated rule name")
	}
}

func TestCorrelationRuleMatches_MitreTechniqueFilter(t *testing.T) {
	rule := makeRule("", "", "T1059", 0)
	if !correlationRuleMatches(rule, makeAlert("high", "", "T1059", 1)) {
		t.Error("mitre match should succeed")
	}
	if correlationRuleMatches(rule, makeAlert("high", "", "T1071", 1)) {
		t.Error("different mitre technique should not match")
	}
}

func TestCorrelationRuleMatches_AgentIDFilter(t *testing.T) {
	rule := makeRule("", "", "", 7)
	if !correlationRuleMatches(rule, makeAlert("high", "", "", 7)) {
		t.Error("matching agentID should succeed")
	}
	if correlationRuleMatches(rule, makeAlert("high", "", "", 99)) {
		t.Error("different agentID should not match")
	}
}

func TestCorrelationRuleMatches_AllConditions(t *testing.T) {
	rule := repositories.EnabledCorrelationRule{
		Severity:       "critical",
		RuleName:       "lateral",
		MitreTechnique: "T1021",
		AgentID:        3,
	}
	match := makeAlert("critical", "Lateral Movement via RDP", "T1021", 3)
	nomatch := makeAlert("critical", "Lateral Movement via RDP", "T1021", 99) // wrong agent
	if !correlationRuleMatches(rule, match) {
		t.Error("all conditions match — should return true")
	}
	if correlationRuleMatches(rule, nomatch) {
		t.Error("wrong agentID — should return false")
	}
}

// ── computeConfidence ─────────────────────────────────────────────────────────

func TestComputeConfidence_Simple(t *testing.T) {
	rule := repositories.EnabledCorrelationRule{CorrelationType: "simple"}
	c := computeConfidence(rule, 0)
	if c < 50 || c > 90 {
		t.Errorf("simple confidence %d out of [50,90]", c)
	}
	// More conditions → higher confidence
	ruleRich := repositories.EnabledCorrelationRule{
		CorrelationType: "simple",
		Severity:        "high",
		RuleName:        "brute",
		MitreTechnique:  "T1110",
		AgentID:         1,
	}
	cRich := computeConfidence(ruleRich, 0)
	if cRich <= c {
		t.Errorf("more conditions should yield higher confidence (%d <= %d)", cRich, c)
	}
}

func TestComputeConfidence_EventCount(t *testing.T) {
	rule := repositories.EnabledCorrelationRule{CorrelationType: "event_count"}
	c0 := computeConfidence(rule, 0)  // exactly at threshold
	c5 := computeConfidence(rule, 5)  // 5 above threshold
	c20 := computeConfidence(rule, 20) // 20 above threshold (should cap)

	if c0 >= c5 {
		t.Errorf("higher signal should increase confidence (%d >= %d)", c0, c5)
	}
	if c20 > 80 {
		t.Errorf("event_count confidence should cap at 80, got %d", c20)
	}
}

func TestComputeConfidence_TemporalOrdered(t *testing.T) {
	ordered := repositories.EnabledCorrelationRule{CorrelationType: "temporal_ordered"}
	unordered := repositories.EnabledCorrelationRule{CorrelationType: "temporal"}
	co := computeConfidence(ordered, 3)
	cu := computeConfidence(unordered, 3)
	if co <= cu {
		t.Errorf("ordered temporal should have higher confidence than unordered (%d <= %d)", co, cu)
	}
	if co > 95 {
		t.Errorf("temporal confidence should cap at 95, got %d", co)
	}
}

// ── vulnerabilityMatchesPattern ───────────────────────────────────────────────

func TestVulnerabilityMatchesPattern(t *testing.T) {
	v := models.Vulnerability{
		CVEID:       "CVE-2023-12345",
		PackageName: "openssl",
		IsKEV:       true,
		EPSSScore:   0.85,
	}

	// vulnerabilityMatchesPattern receives an already-lowercased pattern.
	tests := []struct {
		pattern string
		want    bool
	}{
		{"", true},                // blank matches everything
		{"kev", true},             // IsKEV flag
		{"epss>=0.5", true},       // above threshold
		{"epss>=0.9", false},      // below threshold
		{"epss>=0.85", true},      // exact threshold (>= is inclusive)
		{"cve-2023-12345", true},  // full CVE ID lowercased
		{"cve-2023", true},        // partial CVE ID
		{"openssl", true},         // package name
		{"log4j", false},          // not present
		{"epss>=invalid", false},  // malformed float — no panic
	}

	for _, tc := range tests {
		got := vulnerabilityMatchesPattern(v, tc.pattern)
		if got != tc.want {
			t.Errorf("vulnerabilityMatchesPattern(v, %q) = %v, want %v", tc.pattern, got, tc.want)
		}
	}
}

// ── networkConnectMatchesPattern ──────────────────────────────────────────────

func TestNetworkConnectMatchesPattern(t *testing.T) {
	external := models.ConnectEvent{RemoteAddress: "8.8.8.8:443"}
	internal := models.ConnectEvent{RemoteAddress: "192.168.1.50:80"}
	listen := models.ConnectEvent{RemoteAddress: "0.0.0.0:0"}

	tests := []struct {
		ev      models.ConnectEvent
		pattern string
		want    bool
	}{
		{external, "", true},            // blank matches any real connection
		{external, "external", true},    // external IP
		{external, "internal", false},   // not internal
		{internal, "internal", true},    // RFC1918
		{internal, "external", false},
		{listen, "", false},             // listen placeholder excluded
		{listen, "external", false},
		{external, "8.8.8.8", true},     // substring match
		{external, "1.1.1.1", false},    // substring miss
	}

	for _, tc := range tests {
		patternLower := tc.pattern
		got := networkConnectMatchesPattern(tc.ev, patternLower)
		if got != tc.want {
			t.Errorf("networkConnectMatchesPattern(%v, %q) = %v, want %v",
				tc.ev.RemoteAddress, tc.pattern, got, tc.want)
		}
	}
}
