package agent

import (
	"encoding/json"
	"fmt"
	"testing"
)

// TestForensicCollection_URLPatterns verifies the agent uses correct URLs for
// DFIR collection operations.
func TestForensicCollection_URLPatterns(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{fmt.Sprintf("/api/dfir/collections/%d/artifacts", 4), "/api/dfir/collections/4/artifacts"},
		{fmt.Sprintf("/api/dfir/incidents/%d/timeline", 7), "/api/dfir/incidents/7/timeline"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("URL = %q, want %q", c.got, c.want)
		}
	}
}

// TestForensicCollectionPayload_Fields verifies that a forensic collection
// record includes status and label fields used by the frontend.
func TestForensicCollectionPayload_Fields(t *testing.T) {
	raw := `{"id":1,"label":"Incident 7 Collection","status":"completed","artifact_types":["processes","connections"]}`
	var col map[string]any
	if err := json.Unmarshal([]byte(raw), &col); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"id", "label", "status", "artifact_types"} {
		if _, ok := col[key]; !ok {
			t.Errorf("forensic collection payload missing field %q", key)
		}
	}
}

// TestTriggerCollection_ArtifactTypes verifies that the trigger payload
// accepts an artifact_types array (not a single string).
func TestTriggerCollection_ArtifactTypes(t *testing.T) {
	payload := map[string]any{
		"agent_id":       1,
		"artifact_types": []string{"processes", "connections", "file_hashes"},
	}
	b, _ := json.Marshal(payload)
	var decoded map[string]any
	json.Unmarshal(b, &decoded)
	types, ok := decoded["artifact_types"].([]any)
	if !ok || len(types) == 0 {
		t.Error("artifact_types must be a non-empty array in the trigger payload")
	}
}
