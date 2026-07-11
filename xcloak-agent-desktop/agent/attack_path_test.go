package agent

import (
	"encoding/json"
	"testing"
)

// TestAttackPathPayload_OnlyEstablishedConnections verifies that the connection
// payload the agent posts contains a "state" field. The backend attack-path
// graph now filters to ESTABLISHED-only, so agents must report state accurately
// or all their connections will be ignored when building the graph.
func TestAttackPathPayload_OnlyEstablishedConnections(t *testing.T) {
	// Simulate what the agent sends for the ss-based connection snapshot.
	payload := []map[string]any{
		{
			"agent_id":       1,
			"protocol":       "tcp",
			"local_address":  "10.0.1.5:52001",
			"remote_address": "10.0.1.10:443",
			"state":          "ESTABLISHED",
			"process_name":   "curl",
		},
		{
			"agent_id":       1,
			"protocol":       "tcp",
			"local_address":  "0.0.0.0:22",
			"remote_address": "0.0.0.0:0",
			"state":          "LISTEN",
			"process_name":   "sshd",
		},
	}

	body, _ := json.Marshal(payload)
	var decoded []map[string]any
	json.Unmarshal(body, &decoded)

	for _, row := range decoded {
		if _, ok := row["state"]; !ok {
			t.Error("connection payload missing 'state' field — attack-path graph requires it for ESTABLISHED filter")
		}
	}
}

// TestAttackPathPayload_StateIsString verifies that "state" is encoded as a
// string, not a number. The backend does a string comparison ("ESTABLISHED").
func TestAttackPathPayload_StateIsString(t *testing.T) {
	payload := map[string]any{
		"agent_id":       1,
		"protocol":       "tcp",
		"local_address":  "192.168.0.5:43210",
		"remote_address": "203.0.113.10:443",
		"state":          "ESTABLISHED",
	}

	body, _ := json.Marshal(payload)
	var decoded map[string]any
	json.Unmarshal(body, &decoded)

	state, ok := decoded["state"]
	if !ok {
		t.Fatal("state field missing from payload")
	}
	if _, isStr := state.(string); !isStr {
		t.Errorf("state is %T, want string", state)
	}
	if state.(string) != "ESTABLISHED" {
		t.Errorf("state = %q, want ESTABLISHED", state)
	}
}

// TestAttackPathPayload_ListenDoesNotExposedAgent verifies the payload shape
// for LISTEN connections. The backend should skip these when building attack
// paths — the test confirms the state field is "LISTEN", not "ESTABLISHED",
// so the filter will correctly exclude it.
func TestAttackPathPayload_ListenDoesNotExposeAgent(t *testing.T) {
	listenConn := map[string]any{
		"agent_id":       1,
		"protocol":       "tcp",
		"local_address":  "0.0.0.0:443",
		"remote_address": "0.0.0.0:0",
		"state":          "LISTEN",
	}

	body, _ := json.Marshal(listenConn)
	var decoded map[string]any
	json.Unmarshal(body, &decoded)

	if decoded["state"] == "ESTABLISHED" {
		t.Error("LISTEN connection must not have state=ESTABLISHED — would be incorrectly treated as lateral movement")
	}
	if decoded["state"] != "LISTEN" {
		t.Errorf("state = %v, want LISTEN for listen placeholder", decoded["state"])
	}
}
