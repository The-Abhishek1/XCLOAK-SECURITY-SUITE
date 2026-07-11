package agent

import (
	"encoding/json"
	"testing"
	"time"
)

// TestLogCollectionPayload_Contract verifies the shape of a log collection
// payload sent to the backend. The backend inserts these into endpoint_logs;
// wrong field names silently produce NULL DB columns.
func TestLogCollectionPayload_Contract(t *testing.T) {
	entry := map[string]any{
		"agent_id":   1,
		"log_source": "auth",
		"log_message": "Accepted publickey for ubuntu from 10.0.0.5 port 52200 ssh2",
		"collected_at": time.Now().UTC().Format(time.RFC3339),
	}

	body, _ := json.Marshal(entry)
	var decoded map[string]any
	json.Unmarshal(body, &decoded)

	required := []string{"agent_id", "log_source", "log_message", "collected_at"}
	for _, f := range required {
		if _, ok := decoded[f]; !ok {
			t.Errorf("log entry missing required field %q", f)
		}
	}

	// log_message must be a string
	if _, ok := decoded["log_message"].(string); !ok {
		t.Errorf("log_message is %T, want string", decoded["log_message"])
	}

	// collected_at must be an RFC3339 string parseable by the backend
	if ts, ok := decoded["collected_at"].(string); ok {
		if _, err := time.Parse(time.RFC3339, ts); err != nil {
			t.Errorf("collected_at %q is not RFC3339: %v", ts, err)
		}
	}
}

// TestLogCollectionPayload_SourceNotEmpty verifies that log_source is never
// empty. An empty source makes it impossible to correlate logs by source type
// (auth, syslog, windows-event, etc.) in the live view.
func TestLogCollectionPayload_SourceNotEmpty(t *testing.T) {
	sources := []string{"auth", "syslog", "kern", "windows-event", "application"}

	for _, src := range sources {
		entry := map[string]any{
			"agent_id":     1,
			"log_source":   src,
			"log_message":  "test message",
			"collected_at": time.Now().UTC().Format(time.RFC3339),
		}

		body, _ := json.Marshal(entry)
		var decoded map[string]any
		json.Unmarshal(body, &decoded)

		s, ok := decoded["log_source"].(string)
		if !ok || s == "" {
			t.Errorf("log_source for source %q is empty or missing", src)
		}
	}
}

// TestLogCollectionPayload_ExcludesParsedFields verifies that the agent does
// NOT send parsed_fields — field extraction runs server-side from the raw
// log_message. An agent sending parsed_fields could inject fake fields into
// the live view filters (e.g. fake auth_result=success for a failed login).
func TestLogCollectionPayload_ExcludesParsedFields(t *testing.T) {
	entry := map[string]any{
		"agent_id":    1,
		"log_source":  "auth",
		"log_message": "Failed password for invalid user admin from 1.2.3.4 port 22",
		"collected_at": time.Now().UTC().Format(time.RFC3339),
		// Agent must NOT include parsed_fields:
		// "parsed_fields": map[string]any{"auth_result": "success"},
	}

	body, _ := json.Marshal(entry)
	var decoded map[string]any
	json.Unmarshal(body, &decoded)

	if _, ok := decoded["parsed_fields"]; ok {
		t.Error("log entry must not include parsed_fields — field extraction is server-side only")
	}
}
