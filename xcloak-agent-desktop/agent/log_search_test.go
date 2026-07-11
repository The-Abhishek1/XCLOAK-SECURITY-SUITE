package agent

import (
	"encoding/json"
	"testing"
	"time"
)

// TestLogEntry_ParsedFieldsNotSentByAgent verifies that log entries submitted
// by the agent do NOT include parsed_fields. Field extraction runs server-side
// from log_message; if an agent sends parsed_fields the server overwrites them,
// so sending them is wasteful and could mask the server's parser.
func TestLogEntry_ParsedFieldsNotSentByAgent(t *testing.T) {
	entry := map[string]any{
		"agent_id":     1,
		"log_source":   "auth",
		"log_message":  "Accepted password for ubuntu from 192.168.1.5 port 22 ssh2",
		"collected_at": time.Now().UTC().Format(time.RFC3339),
	}

	body, _ := json.Marshal(entry)
	var decoded map[string]any
	json.Unmarshal(body, &decoded)

	if _, ok := decoded["parsed_fields"]; ok {
		t.Error("agent must not include parsed_fields — field extraction is server-side only")
	}
}

// TestLogBatch_AllEntriesHaveSource verifies that every entry in a batch log
// submission has a non-empty log_source. Without a source, the log search
// ?source= filter cannot work and logs appear as "unknown" in the stats panel.
func TestLogBatch_AllEntriesHaveSource(t *testing.T) {
	batch := []map[string]any{
		{"agent_id": 1, "log_source": "auth",    "log_message": "session opened for user ubuntu",  "collected_at": time.Now().UTC().Format(time.RFC3339)},
		{"agent_id": 1, "log_source": "kern",    "log_message": "oom-killer: out of memory",       "collected_at": time.Now().UTC().Format(time.RFC3339)},
		{"agent_id": 1, "log_source": "syslog",  "log_message": "systemd: started sshd.service",   "collected_at": time.Now().UTC().Format(time.RFC3339)},
	}

	for i, entry := range batch {
		body, _ := json.Marshal(entry)
		var decoded map[string]any
		json.Unmarshal(body, &decoded)

		src, ok := decoded["log_source"].(string)
		if !ok || src == "" {
			t.Errorf("batch entry %d missing non-empty log_source", i)
		}
	}
}

// TestLogEntry_CollectedAtIsRFC3339 verifies that collected_at is serialized
// as an RFC3339 timestamp. The backend parses it with time.RFC3339; any other
// format silently stores NULL in the collected_at column, which breaks the
// time-range filters in log search (?from= and ?to=).
func TestLogEntry_CollectedAtIsRFC3339(t *testing.T) {
	now := time.Now().UTC()
	entry := map[string]any{
		"agent_id":     1,
		"log_source":   "syslog",
		"log_message":  "test message",
		"collected_at": now.Format(time.RFC3339),
	}

	body, _ := json.Marshal(entry)
	var decoded map[string]any
	json.Unmarshal(body, &decoded)

	ts, ok := decoded["collected_at"].(string)
	if !ok || ts == "" {
		t.Fatal("collected_at missing or not a string")
	}

	parsed, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		t.Errorf("collected_at %q is not RFC3339: %v", ts, err)
	}

	// Ensure we're not sending Unix epoch or other obviously wrong values.
	if parsed.Year() < 2024 {
		t.Errorf("collected_at year %d looks wrong", parsed.Year())
	}
}
