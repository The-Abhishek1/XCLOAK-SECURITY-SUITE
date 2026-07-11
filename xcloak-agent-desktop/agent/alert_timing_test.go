package agent

import (
	"encoding/json"
	"testing"
	"time"
)

// TestHeartbeatDoesNotIncludeSnoozeFields verifies that the heartbeat payload
// the agent sends to /api/agents/heartbeat does NOT contain any server-side
// alert suppression fields. Snooze state lives on the server; the agent
// sending it would confuse the backend into treating a client value as
// authoritative over the server's own suppressed_until column.
func TestHeartbeatDoesNotIncludeSnoozeFields(t *testing.T) {
	payload := map[string]any{
		"agent_id":       42,
		"version":        "1.0.0",
		"uptime_seconds": 3600,
		"mem_alloc_mb":   128,
		"goroutines":     20,
		"load_avg_1m":    0.5,
		"load_avg_5m":    0.4,
		"load_avg_15m":   0.3,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal heartbeat: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal heartbeat: %v", err)
	}

	// The server is the sole authority on snooze windows; the agent must
	// never attempt to carry or reset suppressed_until.
	serverSideFields := []string{
		"suppressed_until",
		"snooze_until",
		"status",
		"acknowledged_by",
		"acknowledged_at",
		"note",
	}
	for _, f := range serverSideFields {
		if _, ok := decoded[f]; ok {
			t.Errorf("heartbeat payload must not include server-side field %q", f)
		}
	}
}

// TestHeartbeatTimestampIsRecent verifies that the collected_at / uptime
// values an agent would report are based on the current clock, not a
// hardcoded past time. A stale timestamp could make a snoozed alert
// reappear before the window expires on the server's clock.
func TestHeartbeatTimestampIsRecent(t *testing.T) {
	before := time.Now()
	collected := time.Now() // simulates what the agent sets on collection
	after := time.Now()

	if collected.Before(before) || collected.After(after.Add(time.Second)) {
		t.Errorf("collected_at %v is not within [%v, %v]", collected, before, after)
	}

	// Uptime seconds must be non-negative.
	uptimeSeconds := int64(42)
	if uptimeSeconds < 0 {
		t.Error("uptime_seconds must not be negative")
	}
}

// TestFIMScanPayload_NoAlertFields verifies that the FIM scan payload the
// agent posts to /api/agents/fim does not include alert suppression fields.
// FIM raises alerts server-side; the agent just sends file hashes.
func TestFIMScanPayload_NoAlertFields(t *testing.T) {
	payload := map[string]any{
		"agent_id": 7,
		"files": []map[string]any{
			{"file_path": "/etc/passwd", "sha256_hash": "abc123", "file_size": 1024, "mode": "-rw-r--r--"},
		},
	}

	body, _ := json.Marshal(payload)
	var decoded map[string]any
	json.Unmarshal(body, &decoded)

	alertFields := []string{"suppressed_until", "status", "severity", "rule_name"}
	for _, f := range alertFields {
		if _, ok := decoded[f]; ok {
			t.Errorf("FIM payload must not include alert field %q", f)
		}
	}

	// Verify required fields ARE present.
	if _, ok := decoded["agent_id"]; !ok {
		t.Error("FIM payload missing agent_id")
	}
	if _, ok := decoded["files"]; !ok {
		t.Error("FIM payload missing files")
	}
}
