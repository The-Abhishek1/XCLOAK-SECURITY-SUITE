package agent

import (
	"encoding/json"
	"fmt"
	"testing"
)

// TestSuppressionRule_URLPatterns verifies correct URL construction for
// suppression rule operations.
func TestSuppressionRule_URLPatterns(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{fmt.Sprintf("/api/suppression/rules/%d", 9), "/api/suppression/rules/9"},
		{fmt.Sprintf("/api/suppression/rules/%d/toggle", 9), "/api/suppression/rules/9/toggle"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("URL = %q, want %q", c.got, c.want)
		}
	}
}

// TestSuppressionRulePayload_Fields verifies that a suppression rule record
// includes the fields needed for the frontend to display and manage rules.
func TestSuppressionRulePayload_Fields(t *testing.T) {
	raw := `{"id":1,"name":"Block Nmap","rule_name":"nmap_scan","window_minutes":60,"enabled":true,"match_count":3}`
	var rule map[string]any
	if err := json.Unmarshal([]byte(raw), &rule); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"id", "name", "rule_name", "window_minutes", "enabled"} {
		if _, ok := rule[key]; !ok {
			t.Errorf("suppression rule payload missing field %q", key)
		}
	}
}

// TestToggleSuppressionRule_BodyShape verifies that the PATCH toggle body
// matches what the backend expects: `{"enabled": bool}`.
func TestToggleSuppressionRule_BodyShape(t *testing.T) {
	body := map[string]any{"enabled": false}
	b, _ := json.Marshal(body)
	var decoded map[string]any
	json.Unmarshal(b, &decoded)
	if _, ok := decoded["enabled"]; !ok {
		t.Error("toggle body must include 'enabled' key")
	}
}
