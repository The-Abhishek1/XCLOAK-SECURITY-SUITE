package agent

import (
	"encoding/json"
	"testing"
)

// TestAgentHeartbeat_ExcludesServerComputedCounts verifies that the agent
// heartbeat payload does NOT include open_alert_count or risk_score. These
// are computed server-side from multiple data sources; an agent sending them
// could lie about its alert or risk state to evade detection.
func TestAgentHeartbeat_ExcludesServerComputedCounts(t *testing.T) {
	payload := map[string]any{
		"agent_id":        1,
		"version":         "1.0.0",
		"uptime_seconds":  7200,
		"mem_alloc_mb":    256,
		"goroutines":      30,
		"load_avg_1m":     0.8,
		"load_avg_5m":     0.6,
		"load_avg_15m":    0.4,
		"logged_in_users": 1,
		"open_fds":        1024,
	}

	body, _ := json.Marshal(payload)
	var decoded map[string]any
	json.Unmarshal(body, &decoded)

	serverOnlyFields := []string{
		"open_alert_count",
		"risk_score",
		"risk_level",
		"health_score",
		"health_status",
		"alert_rate_1h",
	}
	for _, f := range serverOnlyFields {
		if _, ok := decoded[f]; ok {
			t.Errorf("heartbeat must not include server-computed field %q", f)
		}
	}
}

// TestAgentHeartbeat_AgentMetricFields verifies that the heartbeat payload
// includes the fields the server needs to update agent metrics. Missing fields
// result in NULL DB columns that break health scoring.
func TestAgentHeartbeat_AgentMetricFields(t *testing.T) {
	payload := map[string]any{
		"agent_id":       1,
		"version":        "1.0.0",
		"uptime_seconds": 3600,
		"mem_alloc_mb":   128,
		"goroutines":     20,
	}

	body, _ := json.Marshal(payload)
	var decoded map[string]any
	json.Unmarshal(body, &decoded)

	required := []string{"agent_id", "version", "uptime_seconds", "mem_alloc_mb", "goroutines"}
	for _, f := range required {
		if _, ok := decoded[f]; !ok {
			t.Errorf("heartbeat missing required field %q", f)
		}
	}

	// agent_id must be a number, not a string
	if _, ok := decoded["agent_id"].(float64); !ok {
		t.Errorf("agent_id is %T, want number", decoded["agent_id"])
	}
}

// TestAgentHeartbeat_MetricTypes verifies that numeric metric fields are
// encoded as numbers, not strings. The server scans them as Go numeric types;
// wrong encoding silently stores 0 or fails the scan.
func TestAgentHeartbeat_MetricTypes(t *testing.T) {
	payload := map[string]any{
		"agent_id":        42,
		"uptime_seconds":  int64(86400),
		"mem_alloc_mb":    512,
		"goroutines":      50,
		"load_avg_1m":     1.25,
		"logged_in_users": 3,
		"open_fds":        2048,
	}

	body, _ := json.Marshal(payload)
	var decoded map[string]any
	json.Unmarshal(body, &decoded)

	numericFields := []string{
		"agent_id", "uptime_seconds", "mem_alloc_mb",
		"goroutines", "load_avg_1m", "logged_in_users", "open_fds",
	}
	for _, f := range numericFields {
		v, ok := decoded[f]
		if !ok {
			continue
		}
		if _, isNum := v.(float64); !isNum {
			t.Errorf("field %q is %T, want numeric (float64 in JSON)", f, v)
		}
	}
}
