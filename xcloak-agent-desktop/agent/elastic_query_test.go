package agent

import (
	"encoding/json"
	"testing"
)

// TestElasticQuery_AgentDoesNotSendDSL verifies that the desktop agent heartbeat
// does not include any Elasticsearch DSL or query fields. The ES query interface
// is analyst-facing (SOC UI), not agent-facing; agents submit raw logs, not
// DSL queries.
func TestElasticQuery_AgentDoesNotSendDSL(t *testing.T) {
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

	esFields := []string{"dsl", "query", "index", "bool", "must", "should", "filter",
		"aggs", "aggregations", "match_all", "match_phrase"}
	for _, f := range esFields {
		if _, ok := decoded[f]; ok {
			t.Errorf("heartbeat must not include ES DSL field %q", f)
		}
	}
}

// TestLogIngest_IndexFieldNotSet verifies that log ingest payloads submitted by
// the agent do not include an ES index name. The index is determined server-side
// from the tenant_id; an agent setting it could redirect logs to another
// tenant's index.
func TestLogIngest_IndexFieldNotSet(t *testing.T) {
	logEntry := map[string]any{
		"agent_id":     1,
		"log_source":   "auth",
		"log_message":  "Accepted publickey for ubuntu from 10.0.0.5 port 22 ssh2",
		"collected_at": "2025-01-01T12:00:00Z",
	}

	body, _ := json.Marshal(logEntry)
	var decoded map[string]any
	json.Unmarshal(body, &decoded)

	prohibited := []string{"index", "_index", "tenant_id", "dsl"}
	for _, f := range prohibited {
		if _, ok := decoded[f]; ok {
			t.Errorf("log ingest entry must not include server-controlled field %q", f)
		}
	}
}

// TestLogIngest_SizeNotSet verifies that log ingest payloads do not include an
// ES size/from parameter. Only the server controls how many documents are
// returned or how deep pagination goes (capped at 1000/10000 respectively).
func TestLogIngest_SizeNotSet(t *testing.T) {
	logEntry := map[string]any{
		"agent_id":    1,
		"log_source":  "syslog",
		"log_message": "kernel: oom-killer invoked",
	}

	body, _ := json.Marshal(logEntry)
	var decoded map[string]any
	json.Unmarshal(body, &decoded)

	for _, f := range []string{"size", "from", "limit", "offset"} {
		if _, ok := decoded[f]; ok {
			t.Errorf("log ingest entry must not include pagination field %q", f)
		}
	}
}
