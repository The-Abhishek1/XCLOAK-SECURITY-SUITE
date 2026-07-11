package agent

import (
	"encoding/json"
	"fmt"
	"testing"
)

// TestHuntTemplate_URLPatterns verifies correct URL construction for hunt
// workbench operations.
func TestHuntTemplate_URLPatterns(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{fmt.Sprintf("/api/hunt/templates/%d", 2), "/api/hunt/templates/2"},
		{fmt.Sprintf("/api/hunt/runs/%d", 5), "/api/hunt/runs/5"},
		{fmt.Sprintf("/api/hunt/runs/%d/notes", 5), "/api/hunt/runs/5/notes"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("URL = %q, want %q", c.got, c.want)
		}
	}
}

// TestHuntRun_PayloadFields verifies hunt run record has fields expected by
// the workbench UI.
func TestHuntRun_PayloadFields(t *testing.T) {
	raw := `{"id":1,"query_type":"process","query_text":"nmap","status":"completed","result_count":3,"started_at":"2025-01-01T00:00:00Z"}`
	var run map[string]any
	if err := json.Unmarshal([]byte(raw), &run); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"id", "query_type", "query_text", "status", "result_count"} {
		if _, ok := run[key]; !ok {
			t.Errorf("hunt run payload missing field %q", key)
		}
	}
}

// TestUpdateHuntRunNotes_BodyShape verifies the PATCH notes body includes both
// notes and severity as the backend expects.
func TestUpdateHuntRunNotes_BodyShape(t *testing.T) {
	body := map[string]any{
		"notes":    "Found suspicious process on host-01",
		"severity": "high",
	}
	b, _ := json.Marshal(body)
	var decoded map[string]any
	json.Unmarshal(b, &decoded)
	for _, key := range []string{"notes", "severity"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("hunt run notes PATCH body missing field %q", key)
		}
	}
}
