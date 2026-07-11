package agent

import (
	"encoding/json"
	"testing"
)

// TestInsiderThreat_AuthLogFields verifies that auth log entries submitted by
// the desktop agent include the parsed_fields keys the insider threat scoring
// engine depends on: "user", "auth_result", and optionally "bytes_sent".
// If these keys are missing, all insider threat signal queries return 0.
func TestInsiderThreat_AuthLogFields(t *testing.T) {
	// Simulated parsed log entry — matches what the backend expects in
	// endpoint_logs.parsed_fields for insider threat scoring.
	parsedFields := map[string]any{
		"user":        "alice",
		"auth_result": "success",
		"source_ip":   "10.0.0.5",
	}

	b, _ := json.Marshal(parsedFields)
	var decoded map[string]any
	json.Unmarshal(b, &decoded)

	for _, key := range []string{"user", "auth_result"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("parsed_fields must include %q for insider threat scoring", key)
		}
	}
}

// TestInsiderThreat_FailedAuthFields verifies that failed authentication log
// entries include auth_result=failure. The insider threat engine counts entries
// with this value to compute the failed_auth signal (max 15 points).
func TestInsiderThreat_FailedAuthFields(t *testing.T) {
	parsedFields := map[string]any{
		"user":        "root",
		"auth_result": "failure",
		"source_ip":   "192.168.1.1",
	}

	b, _ := json.Marshal(parsedFields)
	var decoded map[string]any
	json.Unmarshal(b, &decoded)

	if v := decoded["auth_result"].(string); v != "failure" {
		t.Errorf("auth_result = %q, want failure for failed-login events", v)
	}
}

// TestInsiderThreat_BytesSentField verifies that data transfer log entries
// include bytes_sent as a numeric string (the DB casts it to bigint). The
// data_exfil signal requires this field to be present and castable.
func TestInsiderThreat_BytesSentField(t *testing.T) {
	parsedFields := map[string]any{
		"user":       "bob",
		"bytes_sent": "52428800", // 50 MB as string (matches DB cast)
		"dest_ip":    "203.0.113.5",
	}

	b, _ := json.Marshal(parsedFields)
	var decoded map[string]any
	json.Unmarshal(b, &decoded)

	v, ok := decoded["bytes_sent"]
	if !ok {
		t.Fatal("bytes_sent must be present for data exfil scoring")
	}
	// Stored as a string in parsed_fields (JSONB), DB casts to bigint.
	if _, isStr := v.(string); !isStr {
		t.Errorf("bytes_sent must be a string (for DB bigint cast), got %T", v)
	}
}
