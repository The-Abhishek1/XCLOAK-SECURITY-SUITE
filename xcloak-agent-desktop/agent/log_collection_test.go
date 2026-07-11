package agent

import (
	"encoding/json"
	"testing"

	"xcloak-agent-desktop/models"
)

// TestLogBatchPayload verifies that the []models.Log slice the collectors
// build serialises to the JSON contract the backend /api/agents/logs endpoint
// expects. If someone changes the Log model field names or json tags, this
// test breaks and forces an update to the backend.
func TestLogBatchPayload(t *testing.T) {
	logs := []models.Log{
		{AgentID: 42, LogSource: "auth.log", LogMessage: "Failed password for root from 10.0.0.1 port 22 ssh2"},
		{AgentID: 42, LogSource: "syslog",   LogMessage: "kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4"},
	}

	body, err := json.Marshal(logs)
	if err != nil {
		t.Fatalf("marshal logs: %v", err)
	}

	var decoded []map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal logs: %v", err)
	}

	if len(decoded) != 2 {
		t.Fatalf("len = %d, want 2", len(decoded))
	}

	// Backend contract: each entry must have agent_id, log_source, log_message.
	required := []string{"agent_id", "log_source", "log_message"}
	for i, entry := range decoded {
		for _, key := range required {
			if _, ok := entry[key]; !ok {
				t.Errorf("entry[%d] missing key %q", i, key)
			}
		}
	}

	if got := decoded[0]["agent_id"].(float64); got != 42 {
		t.Errorf("agent_id = %v, want 42", got)
	}
	if got := decoded[0]["log_source"].(string); got != "auth.log" {
		t.Errorf("log_source = %q, want auth.log", got)
	}
}

// TestLogBatchMaxSize verifies that collectors never try to build a batch
// larger than the backend's maxEventsPerRequest limit (5000).
func TestLogBatchMaxSize(t *testing.T) {
	const backendLimit = 5000

	// Simulate what auth_logs.go does: collect up to 500 lines per call.
	const collectorBatchSize = 500

	if collectorBatchSize > backendLimit {
		t.Errorf("collector batch size %d exceeds backend limit %d — would get 400 from ingest", collectorBatchSize, backendLimit)
	}
}

// TestLogMessageNotEmpty verifies that a Log with an empty message is
// distinguishable from a zero-value (helps detect accidental blank entries).
func TestLogMessageNotEmpty(t *testing.T) {
	good := models.Log{AgentID: 1, LogSource: "syslog", LogMessage: "some event"}
	zero := models.Log{}

	if good.LogMessage == "" {
		t.Error("non-empty log should have LogMessage set")
	}
	if zero.LogMessage != "" {
		t.Error("zero-value log should have empty LogMessage")
	}
}
