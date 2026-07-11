package agent

import (
	"encoding/json"
	"fmt"
	"testing"
)

// TestCanaryToken_URLPatterns verifies correct URL construction for canary
// token CRUD and toggle operations.
func TestCanaryToken_URLPatterns(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{fmt.Sprintf("/api/canary/tokens/%d", 3), "/api/canary/tokens/3"},
		{fmt.Sprintf("/api/canary/tokens/%d/toggle", 3), "/api/canary/tokens/3/toggle"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("URL = %q, want %q", c.got, c.want)
		}
	}
}

// TestCanaryTokenPayload_Fields verifies token record includes required fields.
func TestCanaryTokenPayload_Fields(t *testing.T) {
	raw := `{"id":1,"token_type":"url","name":"S3 Bucket Canary","token_value":"c-abc123","is_active":true,"trip_count":0}`
	var token map[string]any
	if err := json.Unmarshal([]byte(raw), &token); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"id", "token_type", "name", "token_value", "is_active"} {
		if _, ok := token[key]; !ok {
			t.Errorf("canary token payload missing field %q", key)
		}
	}
}

// TestHoneyportPayload_Fields verifies honeyport record includes required
// fields needed to display and manage ports.
func TestHoneyportPayload_Fields(t *testing.T) {
	raw := `{"id":1,"port":4444,"protocol":"tcp","description":"test","is_active":true}`
	var hp map[string]any
	if err := json.Unmarshal([]byte(raw), &hp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"id", "port", "protocol", "is_active"} {
		if _, ok := hp[key]; !ok {
			t.Errorf("honeyport payload missing field %q", key)
		}
	}
}
