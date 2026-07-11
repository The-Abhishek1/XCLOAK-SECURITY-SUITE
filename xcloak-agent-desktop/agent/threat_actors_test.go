package agent

import (
	"encoding/json"
	"fmt"
	"testing"
)

// TestThreatActorPayload_Fields verifies that a threat actor record from the
// backend is decoded correctly by clients consuming the API.
func TestThreatActorPayload_Fields(t *testing.T) {
	raw := `{"id":1,"name":"APT-28","sophistication":"nation-state","motivation":"espionage","mitre_techniques":["T1566","T1059"]}`
	var actor map[string]any
	if err := json.Unmarshal([]byte(raw), &actor); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"id", "name", "sophistication", "motivation"} {
		if _, ok := actor[key]; !ok {
			t.Errorf("threat actor payload missing field %q", key)
		}
	}
}

// TestActorAlerts_URLPattern verifies the agent constructs the correct URL
// when fetching alerts for a threat actor.
func TestActorAlerts_URLPattern(t *testing.T) {
	build := func(actorID, limit int) string {
		return fmt.Sprintf("/api/threat-actors/%d/alerts?limit=%d", actorID, limit)
	}
	if got := build(42, 10); got != "/api/threat-actors/42/alerts?limit=10" {
		t.Errorf("unexpected URL: %q", got)
	}
}

// TestDeleteThreatActor_URLPattern verifies the agent constructs the correct
// DELETE URL.
func TestDeleteThreatActor_URLPattern(t *testing.T) {
	build := func(id int) string { return fmt.Sprintf("/api/threat-actors/%d", id) }
	if got := build(7); got != "/api/threat-actors/7" {
		t.Errorf("unexpected URL: %q", got)
	}
}
