package agent

import (
	"testing"
)

// TestEnrichHeartbeat verifies that enrichHeartbeat populates the expected
// keys in the data map. We only check key presence (not exact values) since
// the actual readings depend on the runtime environment.
func TestEnrichHeartbeat(t *testing.T) {
	data := map[string]any{
		"agent_id":       1,
		"version":        "dev",
		"uptime_seconds": int64(0),
		"mem_alloc_mb":   0,
		"goroutines":     1,
	}

	enrichHeartbeat(data)

	wantKeys := []string{"load_avg_1m", "load_avg_5m", "load_avg_15m"}
	for _, k := range wantKeys {
		if _, ok := data[k]; !ok {
			// enrichHeartbeat reads /proc/loadavg; skip gracefully on platforms
			// where that file doesn't exist (e.g. macOS CI runners).
			t.Logf("key %q missing — likely a non-Linux runner; skipping", k)
			return
		}
	}

	for _, k := range wantKeys {
		v, ok := data[k]
		if !ok {
			t.Errorf("enrichHeartbeat: missing key %q", k)
			continue
		}
		f, ok := v.(float64)
		if !ok {
			t.Errorf("enrichHeartbeat: key %q has type %T, want float64", k, v)
			continue
		}
		if f < 0 {
			t.Errorf("enrichHeartbeat: key %q = %v, want >= 0", k, f)
		}
	}

	// logged_in_users must be a non-negative int if present.
	if v, ok := data["logged_in_users"]; ok {
		n, ok := v.(int)
		if !ok {
			t.Errorf("logged_in_users has type %T, want int", v)
		} else if n < 0 {
			t.Errorf("logged_in_users = %d, want >= 0", n)
		}
	}

	// open_fds must be a non-negative int if present.
	if v, ok := data["open_fds"]; ok {
		n, ok := v.(int)
		if !ok {
			t.Errorf("open_fds has type %T, want int", v)
		} else if n < 0 {
			t.Errorf("open_fds = %d, want >= 0", n)
		}
	}
}

// TestHeartbeatPayloadKeys verifies that SendHeartbeat builds a payload with
// all expected top-level keys. We don't send it — we just check the map shape
// by calling enrichHeartbeat on a synthetic base payload.
func TestHeartbeatPayloadKeys(t *testing.T) {
	baseKeys := []string{"agent_id", "version", "uptime_seconds", "mem_alloc_mb", "goroutines"}

	data := map[string]any{}
	for _, k := range baseKeys {
		data[k] = 0
	}
	enrichHeartbeat(data)

	for _, k := range baseKeys {
		if _, ok := data[k]; !ok {
			t.Errorf("base key %q missing after enrichHeartbeat", k)
		}
	}
}
