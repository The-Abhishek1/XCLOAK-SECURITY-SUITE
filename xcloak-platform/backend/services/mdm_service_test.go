package services

import (
	"testing"
)

// ── compareVersions ───────────────────────────────────────────────────────────

func TestCompareVersions_Basic(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"16.0", "16.0", 0},
		{"17.0", "16.0", 1},
		{"15.9", "16.0", -1},
		{"16.0.1", "16.0.0", 1},
		{"16.0.0", "16.0.1", -1},
		{"10.2", "9.99", 1},
		{"1", "2", -1},
		{"2", "2", 0},
		{"13", "12.0.0", 1},
		{"7.4", "7.4.0", 0},
	}
	for _, tc := range cases {
		got := compareVersions(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// ── evaluateRule ──────────────────────────────────────────────────────────────

func boolPtr(b bool) *bool { return &b }

func makeDevice(platform string) MDMDevice {
	return MDMDevice{
		ID:             1,
		TenantID:       1,
		Platform:       platform,
		OSVersion:      "16.0",
		EnrollmentType: "user",
	}
}

func TestEvaluateRule_EncryptionRequired_Pass(t *testing.T) {
	d := makeDevice("ios")
	d.IsEncrypted = boolPtr(true)
	status, _ := evaluateRule(d, MDMPolicyRule{RuleType: "encryption_required"})
	if status != "pass" {
		t.Errorf("expected pass, got %s", status)
	}
}

func TestEvaluateRule_EncryptionRequired_Fail(t *testing.T) {
	d := makeDevice("android")
	d.IsEncrypted = boolPtr(false)
	status, actual := evaluateRule(d, MDMPolicyRule{RuleType: "encryption_required"})
	if status != "fail" {
		t.Errorf("expected fail, got %s", status)
	}
	if actual != "not encrypted" {
		t.Errorf("unexpected actual: %s", actual)
	}
}

func TestEvaluateRule_EncryptionRequired_Unknown(t *testing.T) {
	d := makeDevice("windows")
	d.IsEncrypted = nil
	status, _ := evaluateRule(d, MDMPolicyRule{RuleType: "encryption_required"})
	if status != "unknown" {
		t.Errorf("expected unknown, got %s", status)
	}
}

func TestEvaluateRule_PasscodeRequired_Pass(t *testing.T) {
	d := makeDevice("ios")
	d.HasPasscode = boolPtr(true)
	status, _ := evaluateRule(d, MDMPolicyRule{RuleType: "passcode_required"})
	if status != "pass" {
		t.Errorf("expected pass, got %s", status)
	}
}

func TestEvaluateRule_PasscodeRequired_Fail(t *testing.T) {
	d := makeDevice("android")
	d.HasPasscode = boolPtr(false)
	status, _ := evaluateRule(d, MDMPolicyRule{RuleType: "passcode_required"})
	if status != "fail" {
		t.Errorf("expected fail, got %s", status)
	}
}

func TestEvaluateRule_JailbreakNotAllowed_Pass(t *testing.T) {
	d := makeDevice("ios")
	d.IsJailbroken = false
	status, _ := evaluateRule(d, MDMPolicyRule{RuleType: "jailbreak_not_allowed"})
	if status != "pass" {
		t.Errorf("expected pass, got %s", status)
	}
}

func TestEvaluateRule_JailbreakNotAllowed_Fail(t *testing.T) {
	d := makeDevice("ios")
	d.IsJailbroken = true
	status, actual := evaluateRule(d, MDMPolicyRule{RuleType: "jailbreak_not_allowed"})
	if status != "fail" {
		t.Errorf("expected fail, got %s", status)
	}
	if actual != "jailbroken/rooted" {
		t.Errorf("unexpected actual: %s", actual)
	}
}

func TestEvaluateRule_DeveloperModeOff_Pass(t *testing.T) {
	d := makeDevice("android")
	d.DeveloperModeOn = false
	status, _ := evaluateRule(d, MDMPolicyRule{RuleType: "developer_mode_off"})
	if status != "pass" {
		t.Errorf("expected pass, got %s", status)
	}
}

func TestEvaluateRule_DeveloperModeOff_Fail(t *testing.T) {
	d := makeDevice("android")
	d.DeveloperModeOn = true
	status, _ := evaluateRule(d, MDMPolicyRule{RuleType: "developer_mode_off"})
	if status != "fail" {
		t.Errorf("expected fail, got %s", status)
	}
}

func TestEvaluateRule_FirewallRequired_Pass(t *testing.T) {
	d := makeDevice("macos")
	d.FirewallEnabled = boolPtr(true)
	status, _ := evaluateRule(d, MDMPolicyRule{RuleType: "firewall_required"})
	if status != "pass" {
		t.Errorf("expected pass, got %s", status)
	}
}

func TestEvaluateRule_FirewallRequired_Fail(t *testing.T) {
	d := makeDevice("macos")
	d.FirewallEnabled = boolPtr(false)
	status, _ := evaluateRule(d, MDMPolicyRule{RuleType: "firewall_required"})
	if status != "fail" {
		t.Errorf("expected fail, got %s", status)
	}
}

func TestEvaluateRule_FirewallRequired_Unknown(t *testing.T) {
	d := makeDevice("macos")
	d.FirewallEnabled = nil
	status, _ := evaluateRule(d, MDMPolicyRule{RuleType: "firewall_required"})
	if status != "unknown" {
		t.Errorf("expected unknown, got %s", status)
	}
}

func TestEvaluateRule_MinOSVersion_Pass(t *testing.T) {
	d := makeDevice("ios")
	d.OSVersion = "17.0"
	status, _ := evaluateRule(d, MDMPolicyRule{RuleType: "min_os_version", Value: "16.0"})
	if status != "pass" {
		t.Errorf("expected pass, got %s", status)
	}
}

func TestEvaluateRule_MinOSVersion_Fail(t *testing.T) {
	d := makeDevice("ios")
	d.OSVersion = "15.0"
	status, _ := evaluateRule(d, MDMPolicyRule{RuleType: "min_os_version", Value: "16.0"})
	if status != "fail" {
		t.Errorf("expected fail, got %s", status)
	}
}

func TestEvaluateRule_MinOSVersion_Equal(t *testing.T) {
	d := makeDevice("ios")
	d.OSVersion = "16.0"
	status, _ := evaluateRule(d, MDMPolicyRule{RuleType: "min_os_version", Value: "16.0"})
	if status != "pass" {
		t.Errorf("expected pass (equal), got %s", status)
	}
}

func TestEvaluateRule_EnrollmentTypeReq_Pass(t *testing.T) {
	d := makeDevice("ios")
	d.EnrollmentType = "supervised"
	status, _ := evaluateRule(d, MDMPolicyRule{RuleType: "enrollment_type_req", Value: "supervised"})
	if status != "pass" {
		t.Errorf("expected pass, got %s", status)
	}
}

func TestEvaluateRule_EnrollmentTypeReq_Fail(t *testing.T) {
	d := makeDevice("android")
	d.EnrollmentType = "user"
	status, _ := evaluateRule(d, MDMPolicyRule{RuleType: "enrollment_type_req", Value: "corporate"})
	if status != "fail" {
		t.Errorf("expected fail, got %s", status)
	}
}

func TestEvaluateRule_SupervisedRequired_Pass(t *testing.T) {
	d := makeDevice("ios")
	d.IsSupervised = true
	status, _ := evaluateRule(d, MDMPolicyRule{RuleType: "supervised_required"})
	if status != "pass" {
		t.Errorf("expected pass, got %s", status)
	}
}

func TestEvaluateRule_SupervisedRequired_Fail(t *testing.T) {
	d := makeDevice("ios")
	d.IsSupervised = false
	status, _ := evaluateRule(d, MDMPolicyRule{RuleType: "supervised_required"})
	if status != "fail" {
		t.Errorf("expected fail, got %s", status)
	}
}

func TestEvaluateRule_Unknown_RuleType(t *testing.T) {
	d := makeDevice("ios")
	status, _ := evaluateRule(d, MDMPolicyRule{RuleType: "not_a_real_rule"})
	if status != "unknown" {
		t.Errorf("expected unknown for unrecognised rule type, got %s", status)
	}
}

// ── policyAppliesToDevice ─────────────────────────────────────────────────────

func TestPolicyApplies_EmptyPlatforms_MatchesAll(t *testing.T) {
	p := MDMPolicy{Platforms: []string{}}
	d := makeDevice("ios")
	if !policyAppliesToDevice(p, d) {
		t.Error("empty platforms should match all devices")
	}
}

func TestPolicyApplies_MatchingPlatform(t *testing.T) {
	p := MDMPolicy{Platforms: []string{"ios", "android"}}
	d := makeDevice("ios")
	if !policyAppliesToDevice(p, d) {
		t.Error("policy should apply to ios device")
	}
}

func TestPolicyApplies_NonMatchingPlatform(t *testing.T) {
	p := MDMPolicy{Platforms: []string{"windows", "macos"}}
	d := makeDevice("ios")
	if policyAppliesToDevice(p, d) {
		t.Error("windows/macos policy should not apply to ios device")
	}
}

func TestPolicyApplies_CaseInsensitive(t *testing.T) {
	p := MDMPolicy{Platforms: []string{"IOS"}}
	d := makeDevice("ios")
	if !policyAppliesToDevice(p, d) {
		t.Error("platform match should be case-insensitive")
	}
}
