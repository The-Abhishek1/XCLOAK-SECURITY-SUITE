package agent

import (
	"encoding/json"
	"testing"

	"xcloak-agent-desktop/models"
)

// TestLogIngest_SourceFieldPresent verifies that log entries submitted by the
// desktop agent always include log_source. The backend uses this field to route
// entries to the correct log source record and for display in the Live Logs page.
func TestLogIngest_SourceFieldPresent(t *testing.T) {
	for _, source := range []string{"auth.log", "syslog", "kern.log", "dpkg.log"} {
		entry := models.Log{
			AgentID:    1,
			LogSource:  source,
			LogMessage: "test event",
		}
		b, _ := json.Marshal(entry)
		var m map[string]any
		json.Unmarshal(b, &m)

		if v, ok := m["log_source"]; !ok || v == "" {
			t.Errorf("log_source missing or empty for source %q", source)
		}
	}
}

// TestLogIngest_NoAPIKeyField verifies that log ingest payloads from the desktop
// agent do not include an api_key field. Desktop agents authenticate via agent
// token (Authorization header), not the HTTP log-source API key mechanism.
func TestLogIngest_NoAPIKeyField(t *testing.T) {
	entry := models.Log{
		AgentID:    1,
		LogSource:  "auth.log",
		LogMessage: "Accepted publickey for ubuntu from 10.0.0.5 port 22 ssh2",
	}
	b, _ := json.Marshal(entry)
	var m map[string]any
	json.Unmarshal(b, &m)

	prohibited := []string{"api_key", "x_api_key", "key", "token"}
	for _, f := range prohibited {
		if _, ok := m[f]; ok {
			t.Errorf("log ingest must not include auth field %q (agents use agent token, not log-source API key)", f)
		}
	}
}

// TestLogIngest_SourceIsString verifies that log_source serialises as a string,
// not an integer or bool. The backend log_sources.source_type column and all
// display queries expect string values.
func TestLogIngest_SourceIsString(t *testing.T) {
	entry := models.Log{AgentID: 1, LogSource: "syslog", LogMessage: "startup"}
	b, _ := json.Marshal(entry)
	var m map[string]any
	json.Unmarshal(b, &m)

	v, ok := m["log_source"]
	if !ok {
		t.Fatal("log_source field missing")
	}
	if _, isStr := v.(string); !isStr {
		t.Errorf("log_source must be a string, got %T", v)
	}
}
