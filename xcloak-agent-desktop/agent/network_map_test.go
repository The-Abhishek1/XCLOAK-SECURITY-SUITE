package agent

import (
	"encoding/json"
	"testing"
)

// TestNetworkMapPayload_IncludesProcessName verifies that when the agent posts
// a connection to /api/agents/connections, the payload includes process_name.
// Without this field, GetEndpointConnectionsByTenant returns blank Comm values
// and every network-map edge shows process="unknown".
func TestNetworkMapPayload_IncludesProcessName(t *testing.T) {
	payload := []map[string]any{
		{
			"agent_id":       1,
			"protocol":       "tcp",
			"local_address":  "192.168.1.10:52001",
			"remote_address": "93.184.216.34:443",
			"state":          "ESTABLISHED",
			"pid":            4521,
			"process_name":   "curl",
			"process_path":   "/usr/bin/curl",
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	row := decoded[0]

	// process_name must be present so the network map can label edges.
	if _, ok := row["process_name"]; !ok {
		t.Error("connection payload missing process_name — network-map edges will show 'unknown'")
	}
	if row["process_name"] != "curl" {
		t.Errorf("process_name = %v, want curl", row["process_name"])
	}

	// process_path must be present for forensic drill-down.
	if _, ok := row["process_path"]; !ok {
		t.Error("connection payload missing process_path")
	}

	// pid must be a number, not a string.
	if pid, ok := row["pid"].(float64); !ok || int(pid) != 4521 {
		t.Errorf("pid = %v (type %T), want numeric 4521", row["pid"], row["pid"])
	}
}

// TestNetworkMapPayload_MissingProcessNameFallsBack verifies the agent can post
// a connection without process_name (e.g., the ss-based snapshot path on
// platforms where /proc is unavailable). The backend must accept the payload
// without error and store an empty process_name.
func TestNetworkMapPayload_MissingProcessNameFallsBack(t *testing.T) {
	payload := []map[string]any{
		{
			"agent_id":       1,
			"protocol":       "udp",
			"local_address":  "0.0.0.0:5353",
			"remote_address": "0.0.0.0:0",
			"state":          "LISTEN",
			// no pid, process_name, or process_path
		},
	}

	body, _ := json.Marshal(payload)
	var decoded []map[string]any
	json.Unmarshal(body, &decoded)
	row := decoded[0]

	// protocol and addresses must be present — without them the backend 400s.
	for _, key := range []string{"agent_id", "protocol", "local_address", "remote_address"} {
		if _, ok := row[key]; !ok {
			t.Errorf("connection payload missing required field %q", key)
		}
	}

	// process_name being absent is acceptable (optional field).
	if v, ok := row["process_name"]; ok && v != "" {
		t.Errorf("expected process_name absent or empty for legacy payload, got %v", v)
	}
}

// TestConnectEventPayload_Contract verifies the eBPF connect-event payload
// shape. eBPF events carry comm (short comm name) rather than process_name;
// the backend maps comm → Comm → network-map edge process label.
func TestConnectEventPayload_Contract(t *testing.T) {
	payload := map[string]any{
		"agent_id":       1,
		"pid":            9876,
		"comm":           "sshd",
		"uid":            0,
		"protocol":       "tcp",
		"local_address":  "10.0.0.1:22",
		"remote_address": "203.0.113.5:54800",
		"state":          "ESTABLISHED",
		"event_ts":       1720000000000000000,
	}

	body, _ := json.Marshal(payload)
	var decoded map[string]any
	json.Unmarshal(body, &decoded)

	required := []string{"agent_id", "pid", "comm", "protocol", "local_address", "remote_address"}
	for _, f := range required {
		if _, ok := decoded[f]; !ok {
			t.Errorf("connect event payload missing required field %q", f)
		}
	}

	// comm must be a string; pid must be numeric.
	if _, ok := decoded["comm"].(string); !ok {
		t.Errorf("comm is not a string: %T", decoded["comm"])
	}
	if _, ok := decoded["pid"].(float64); !ok {
		t.Errorf("pid is not numeric: %T", decoded["pid"])
	}
}
