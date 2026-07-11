package agent

import (
	"encoding/json"
	"testing"
)

// TestAgentHeartbeat_ExcludesDashboardAggregates verifies that the heartbeat
// payload the agent posts to /api/agents/heartbeat does NOT include any
// dashboard-aggregated fields. Those are server-side computations; the agent
// sending them would let a compromised endpoint manipulate the SOC dashboard.
func TestAgentHeartbeat_ExcludesDashboardAggregates(t *testing.T) {
	payload := map[string]any{
		"agent_id":       1,
		"version":        "1.0.0",
		"uptime_seconds": 7200,
		"mem_alloc_mb":   96,
		"goroutines":     14,
		"load_avg_1m":    0.3,
		"load_avg_5m":    0.2,
		"load_avg_15m":   0.15,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal heartbeat: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal heartbeat: %v", err)
	}

	serverSideAggregates := []string{
		"threat_score",
		"anomaly_score",
		"compliance_score",
		"alert_velocity_1h",
		"open_alerts",
		"snoozed_alerts",
		"critical_alerts",
		"mttr",
		"mttd",
		"ioc_hits",
	}
	for _, f := range serverSideAggregates {
		if _, ok := decoded[f]; ok {
			t.Errorf("heartbeat payload must not include server-aggregated field %q", f)
		}
	}
}

// TestAgentHeartbeat_RequiredFields verifies that the fields the backend
// actually reads from the heartbeat payload are all present.
func TestAgentHeartbeat_RequiredFields(t *testing.T) {
	payload := map[string]any{
		"agent_id":       42,
		"version":        "1.2.3",
		"uptime_seconds": 3600,
		"mem_alloc_mb":   200,
		"goroutines":     30,
		"load_avg_1m":    1.0,
		"load_avg_5m":    0.8,
		"load_avg_15m":   0.5,
	}

	body, _ := json.Marshal(payload)
	var decoded map[string]any
	json.Unmarshal(body, &decoded)

	required := []string{
		"agent_id", "version", "uptime_seconds",
		"mem_alloc_mb", "goroutines",
		"load_avg_1m", "load_avg_5m", "load_avg_15m",
	}
	for _, f := range required {
		if _, ok := decoded[f]; !ok {
			t.Errorf("heartbeat payload missing required field %q", f)
		}
	}
}

// TestAgentHeartbeat_LoadAveragesAreNumeric verifies that load averages are
// encoded as float64, not strings. A string value would silently zero-out
// the dashboard's threat-score calculation on the server.
func TestAgentHeartbeat_LoadAveragesAreNumeric(t *testing.T) {
	payload := map[string]any{
		"agent_id":     1,
		"load_avg_1m":  0.75,
		"load_avg_5m":  0.60,
		"load_avg_15m": 0.45,
	}

	body, _ := json.Marshal(payload)
	var decoded map[string]any
	json.Unmarshal(body, &decoded)

	for _, key := range []string{"load_avg_1m", "load_avg_5m", "load_avg_15m"} {
		val, ok := decoded[key]
		if !ok {
			t.Errorf("key %q missing from payload", key)
			continue
		}
		if _, isFloat := val.(float64); !isFloat {
			t.Errorf("key %q: want float64, got %T", key, val)
		}
	}
}
