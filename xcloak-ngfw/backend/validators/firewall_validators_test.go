package validators

import (
	"testing"

	"xcloak-ngfw/models"
)

func TestValidateFirewallRule(t *testing.T) {
	tests := []struct {
		name    string
		rule    models.FirewallRule
		wantErr bool
		errMsg  string
	}{
		{"valid rule", models.FirewallRule{Name: "block-ssh", Port: 22}, false, ""},
		{"empty name", models.FirewallRule{Name: "", Port: 80}, true, "name required"},
		{"port zero", models.FirewallRule{Name: "test", Port: 0}, true, "invalid port"},
		{"port negative", models.FirewallRule{Name: "test", Port: -1}, true, "invalid port"},
		{"port 65535 valid", models.FirewallRule{Name: "test", Port: 65535}, false, ""},
		{"port 65536 invalid", models.FirewallRule{Name: "test", Port: 65536}, true, "invalid port"},
		{"port 1 valid", models.FirewallRule{Name: "test", Port: 1}, false, ""},
		{"empty name and zero port", models.FirewallRule{Name: "", Port: 0}, true, "name required"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFirewallRule(tc.rule)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error %q, got nil", tc.errMsg)
				} else if err.Error() != tc.errMsg {
					t.Errorf("error = %q, want %q", err.Error(), tc.errMsg)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
