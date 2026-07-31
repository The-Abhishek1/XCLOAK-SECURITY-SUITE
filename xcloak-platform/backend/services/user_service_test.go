package services

import (
	"testing"

	"xcloak-platform/models"
)

func TestValidatePasswordComplexity_TenantConfigurable(t *testing.T) {
	strict := models.TenantSecurityPolicy{MinPasswordLength: 12, RequireSpecialChars: true, RequireNumbers: true}
	relaxed := models.TenantSecurityPolicy{MinPasswordLength: 8, RequireSpecialChars: false, RequireNumbers: false}

	cases := []struct {
		name    string
		pw      string
		policy  models.TenantSecurityPolicy
		wantErr bool
	}{
		{"too short for strict policy", "Short1!", strict, true},
		{"meets strict policy", "LongEnough1!", strict, false},
		{"missing special char rejected by strict", "LongEnough1", strict, true},
		{"missing digit rejected by strict", "LongEnough!", strict, true},
		{"same password accepted by relaxed policy (no special/digit required)", "LongEnough", relaxed, false},
		{"still needs upper+lower even under relaxed policy", "longenough", relaxed, true},
		{"below the hard 8-char floor even if policy asks for less", "Ab1!", relaxed, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePasswordComplexity(tc.pw, tc.policy)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidatePasswordComplexity(%q, %+v) error = %v, wantErr %v", tc.pw, tc.policy, err, tc.wantErr)
			}
		})
	}
}
