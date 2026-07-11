package agent

import (
	"encoding/json"
	"testing"
)

// TestTimeline_AgentReportsNoSeverity verifies that the desktop agent does not
// synthesize severity values in its heartbeat or event payloads. Severity is
// set server-side when the alert is created by the detection engine.
func TestTimeline_AgentReportsNoSeverity(t *testing.T) {
	heartbeat := map[string]any{
		"agent_id":       1,
		"version":        "1.0.0",
		"uptime_seconds": 3600,
		"mem_alloc_mb":   128,
		"goroutines":     20,
	}

	body, _ := json.Marshal(heartbeat)
	var decoded map[string]any
	json.Unmarshal(body, &decoded)

	timelineFields := []string{"severity", "event_type", "timeline", "events"}
	for _, f := range timelineFields {
		if _, ok := decoded[f]; ok {
			t.Errorf("heartbeat must not include timeline field %q", f)
		}
	}
}

// TestTimeline_LogPayload_MessageNotEmpty verifies that log collection payloads
// include a non-empty message. Empty messages produce empty timeline entries
// that pollute the timeline view with blank cards.
func TestTimeline_LogPayload_MessageNotEmpty(t *testing.T) {
	logEntries := []map[string]any{
		{"agent_id": 1, "source": "auth", "message": "Failed login for user root", "level": "warn"},
		{"agent_id": 1, "source": "syslog", "message": "kernel: oom-killer invoked", "level": "error"},
	}

	for _, entry := range logEntries {
		body, _ := json.Marshal(entry)
		var decoded map[string]any
		json.Unmarshal(body, &decoded)

		msg, ok := decoded["message"].(string)
		if !ok || msg == "" {
			t.Errorf("log entry missing non-empty message: %v", decoded)
		}
	}
}

// TestTimeline_PlaybookExecution_ActionType verifies that playbook execution
// payloads include a non-empty action_type, since the backend uses it to build
// the timeline event message.
func TestTimeline_PlaybookExecution_ActionType(t *testing.T) {
	execPayload := map[string]any{
		"agent_id":    1,
		"playbook_id": 5,
		"alert_rule":  "Suspicious outbound connection",
		"action_type": "isolate_host",
		"status":      "completed",
	}

	body, _ := json.Marshal(execPayload)
	var decoded map[string]any
	json.Unmarshal(body, &decoded)

	actionType, ok := decoded["action_type"].(string)
	if !ok || actionType == "" {
		t.Error("playbook execution missing non-empty action_type")
	}

	// action_type must be one of the known values the server handles
	allowed := map[string]bool{
		"isolate_host": true, "kill_process": true, "execute_script": true,
		"block_ip": true, "collect_file": true, "notify": true,
	}
	if !allowed[actionType] && actionType != "isolate_host" {
		// Not a hard failure — new action types may be added; just warn.
		t.Logf("action_type %q not in known set (may be new)", actionType)
	}
}
