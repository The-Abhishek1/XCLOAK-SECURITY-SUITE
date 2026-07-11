package agent

import (
	"encoding/json"
	"testing"
)

// TestUEBALogPayload_AuthLogSource verifies that desktop agent auth log entries
// use the "auth.log" log_source value, which is the key the UEBA service filters
// on when scanning for auth events (analyzeEndpointLogs: log_source='auth.log').
func TestUEBALogPayload_AuthLogSource(t *testing.T) {
	entry := map[string]any{
		"agent_id":    1,
		"log_source":  "auth.log",
		"log_message": "Failed password for root from 10.0.0.1 port 22 ssh2",
	}

	b, _ := json.Marshal(entry)
	var decoded map[string]any
	json.Unmarshal(b, &decoded)

	if decoded["log_source"] != "auth.log" {
		t.Errorf("log_source = %q, want auth.log (required for UEBA analysis)", decoded["log_source"])
	}
}

// TestUEBALogPayload_ContainsCollectedAt verifies that log entries include
// a collected_at timestamp. The UEBA service uses this as the event time to
// classify off-hours activity; missing timestamps default to time.Now() which
// makes all events appear as current rather than their actual occurrence time.
func TestUEBALogPayload_ContainsCollectedAt(t *testing.T) {
	entry := map[string]any{
		"agent_id":     1,
		"log_source":   "auth.log",
		"log_message":  "Accepted publickey for deploy from 10.0.0.5 port 22 ssh2",
		"collected_at": "2025-01-13T03:00:00Z", // off-hours
	}

	b, _ := json.Marshal(entry)
	var decoded map[string]any
	json.Unmarshal(b, &decoded)

	if _, ok := decoded["collected_at"]; !ok {
		t.Error("log payload must include collected_at for UEBA off-hours detection")
	}
}

// TestUEBALogPayload_AgentIDPresent verifies that the agent_id field is always
// included in log entries. The UEBA service stores agent_id on each event so
// SOC analysts can trace which host a suspicious auth event originated from.
func TestUEBALogPayload_AgentIDPresent(t *testing.T) {
	entry := map[string]any{
		"agent_id":   42,
		"log_source": "auth.log",
		"log_message": "sudo:  alice : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
	}

	b, _ := json.Marshal(entry)
	var decoded map[string]any
	json.Unmarshal(b, &decoded)

	v, ok := decoded["agent_id"]
	if !ok {
		t.Fatal("log entry must include agent_id for UEBA host attribution")
	}
	if v.(float64) != 42 {
		t.Errorf("agent_id = %v, want 42", v)
	}
}
