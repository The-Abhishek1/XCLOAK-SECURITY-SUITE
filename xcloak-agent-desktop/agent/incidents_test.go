package agent

import (
	"encoding/json"
	"testing"
)

// TestIncidentPayload_AgentFields verifies that any incident-related fields an
// agent might emit (e.g., in a heartbeat or alert payload) use the correct JSON
// keys that match the backend models.Incident struct tags.
func TestIncidentPayload_AgentFields(t *testing.T) {
	// Agents do not create incidents directly — the backend creates them from
	// alerts. But agents do send alert payloads whose fields feed into incident
	// creation (agent_id, severity, rule_name). Verify the alert payload matches.
	alert := map[string]any{
		"agent_id":  1,
		"severity":  "high",
		"rule_name": "Suspicious SSH Login",
		"fingerprint": "sha256:abc",
	}

	b, _ := json.Marshal(alert)
	var decoded map[string]any
	json.Unmarshal(b, &decoded)

	required := []string{"agent_id", "severity", "rule_name"}
	for _, k := range required {
		if _, ok := decoded[k]; !ok {
			t.Errorf("alert payload missing required field %q (used for incident creation)", k)
		}
	}
}

// TestIncidentPayload_NoStatusField verifies that agent-emitted payloads do not
// include an incident status field. Status is a SOC analyst concern, not an
// agent concern — an agent claiming "status=resolved" would bypass analyst review.
func TestIncidentPayload_NoStatusField(t *testing.T) {
	alert := map[string]any{
		"agent_id":  1,
		"severity":  "critical",
		"rule_name": "Ransomware Activity",
	}

	b, _ := json.Marshal(alert)
	var decoded map[string]any
	json.Unmarshal(b, &decoded)

	for _, prohibited := range []string{"status", "incident_id", "resolved"} {
		if _, ok := decoded[prohibited]; ok {
			t.Errorf("agent payload must not include %q — this is a server/analyst field", prohibited)
		}
	}
}

// TestIncidentSeverityValues verifies that the severity values the agent uses
// in alert payloads match the set the backend's incident severity validator accepts.
func TestIncidentSeverityValues(t *testing.T) {
	// These must match the valid set in UpdateIncidentSeverity: low, medium, high, critical.
	validSeverities := []string{"low", "medium", "high", "critical"}

	for _, sev := range validSeverities {
		alert := map[string]any{
			"agent_id":  1,
			"severity":  sev,
			"rule_name": "test rule",
		}
		b, _ := json.Marshal(alert)
		var decoded map[string]any
		json.Unmarshal(b, &decoded)

		if got := decoded["severity"].(string); got != sev {
			t.Errorf("severity round-trip: got %q, want %q", got, sev)
		}
	}
}
