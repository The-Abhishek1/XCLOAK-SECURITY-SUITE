package validators

import (
	"testing"

	"xcloak-platform/models"
)

func TestValidateFirewallRule(t *testing.T) {
	tests := []struct {
		name    string
		rule    models.FirewallRule
		wantErr bool
		errMsg  string
	}{
		{"valid rule single port",  models.FirewallRule{Name: "block-ssh", Port: 22, Action: "deny"}, false, ""},
		{"valid rule any port",     models.FirewallRule{Name: "block-all", Port: 0, Action: "deny"}, false, ""},
		{"valid rule port range",   models.FirewallRule{Name: "web", PortRange: "80,443", Action: "allow"}, false, ""},
		{"valid rule range dash",   models.FirewallRule{Name: "hi-ports", PortRange: "8000-9000", Action: "allow"}, false, ""},
		{"empty name",              models.FirewallRule{Name: "", Port: 80, Action: "allow"}, true, "name required"},
		{"missing action",          models.FirewallRule{Name: "test", Port: 80}, true, "action required"},
		{"invalid action",          models.FirewallRule{Name: "test", Port: 80, Action: "block"}, true, ""},
		{"port negative",           models.FirewallRule{Name: "test", Port: -1, Action: "allow"}, true, "port must be between 1 and 65535"},
		{"port 65535 valid",        models.FirewallRule{Name: "test", Port: 65535, Action: "allow"}, false, ""},
		{"port 65536 invalid",      models.FirewallRule{Name: "test", Port: 65536, Action: "allow"}, true, "port must be between 1 and 65535"},
		{"port 1 valid",            models.FirewallRule{Name: "test", Port: 1, Action: "allow"}, false, ""},
		{"invalid direction",       models.FirewallRule{Name: "test", Action: "allow", Direction: "lateral"}, true, ""},
		{"valid direction in",      models.FirewallRule{Name: "test", Action: "allow", Direction: "in"}, false, ""},
		{"valid direction both",    models.FirewallRule{Name: "test", Action: "allow", Direction: "both"}, false, ""},
		{"invalid cidr",            models.FirewallRule{Name: "test", Action: "allow", SourceIP: "999.1.2.3"}, true, ""},
		{"valid cidr",              models.FirewallRule{Name: "test", Action: "allow", SourceIP: "10.0.0.0/8"}, false, ""},
		{"invalid port range",      models.FirewallRule{Name: "test", Action: "allow", PortRange: "abc"}, true, ""},
		{"port range reversed",     models.FirewallRule{Name: "test", Action: "allow", PortRange: "9000-80"}, true, ""},
		{"empty name and zero port", models.FirewallRule{Name: "", Port: 0, Action: "allow"}, true, "name required"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFirewallRule(tc.rule)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if tc.errMsg != "" && err.Error() != tc.errMsg {
					t.Errorf("error = %q, want %q", err.Error(), tc.errMsg)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidatePortRange(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"80", false},
		{"443", false},
		{"8000-9000", false},
		{"80,443,8080", false},
		{"80,8000-9000,443", false},
		{"0", true},
		{"65536", true},
		{"9000-8000", true}, // reversed
		{"abc", true},
		{"80-abc", true},
	}
	for _, tc := range tests {
		err := ValidatePortRange(tc.input)
		if tc.wantErr && err == nil {
			t.Errorf("input %q: expected error, got nil", tc.input)
		} else if !tc.wantErr && err != nil {
			t.Errorf("input %q: unexpected error: %v", tc.input, err)
		}
	}
}

func TestCIDROverlaps(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"10.0.0.0/8", "10.1.0.0/16", true},    // subnet of parent
		{"10.0.0.0/8", "192.168.0.0/16", false}, // no overlap
		{"any", "10.0.0.0/8", true},              // wildcard
		{"", "10.0.0.1", true},                   // empty = any
		{"10.0.0.1", "10.0.0.1", true},           // same host
		{"192.168.1.0/24", "192.168.2.0/24", false}, // adjacent, no overlap
	}
	for _, tc := range tests {
		got := CIDROverlaps(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("CIDROverlaps(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
