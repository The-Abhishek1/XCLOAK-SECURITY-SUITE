//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"xcloak-platform/repositories"
)

// ── ReceiveConnections ──────────────────────────────────────────────────────

// TestReceiveConnections_StoresProcessFields verifies that a connection payload
// containing pid + process_name + process_path is stored and retrievable.
// This is the core regression test for the process binding feature: if the
// INSERT drops the columns, GetConnectionsByAgent returns empty strings.
func TestReceiveConnections_StoresProcessFields(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)

	r := gin.New()
	r.Use(injectClaims(1, 1, "admin"))
	r.POST("/api/agents/connections", ReceiveConnections)

	pid := 1234
	payload := []map[string]any{
		{
			"agent_id":       agentID,
			"protocol":       "tcp",
			"local_address":  "127.0.0.1:54321",
			"remote_address": "93.184.216.34:443",
			"state":          "ESTABLISHED",
			"pid":            pid,
			"process_name":   "curl",
			"process_path":   "/usr/bin/curl",
		},
	}
	body, _ := json.Marshal(payload)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/agents/connections", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("ReceiveConnections: status = %d; body: %s", w.Code, w.Body.String())
	}

	conns, err := repositories.GetConnectionsByAgent(fmt.Sprintf("%d", agentID))
	if err != nil {
		t.Fatalf("GetConnectionsByAgent: %v", err)
	}
	if len(conns) == 0 {
		t.Fatal("no connections stored after POST")
	}

	c := conns[0]
	if c.ProcessName != "curl" {
		t.Errorf("process_name = %q, want curl", c.ProcessName)
	}
	if c.ProcessPath != "/usr/bin/curl" {
		t.Errorf("process_path = %q, want /usr/bin/curl", c.ProcessPath)
	}
	if c.PID == nil || *c.PID != pid {
		t.Errorf("pid = %v, want %d", c.PID, pid)
	}
	if c.Protocol != "tcp" {
		t.Errorf("protocol = %q, want tcp", c.Protocol)
	}
	if c.RemoteAddress != "93.184.216.34:443" {
		t.Errorf("remote_address = %q, want 93.184.216.34:443", c.RemoteAddress)
	}
}

// TestReceiveConnections_ReplacesSnapshot verifies that posting a new batch
// replaces the previous snapshot (not appends), because endpoint connections
// are a point-in-time snapshot, not an event log.
func TestReceiveConnections_ReplacesSnapshot(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)

	r := gin.New()
	r.Use(injectClaims(1, 1, "admin"))
	r.POST("/api/agents/connections", ReceiveConnections)

	post := func(conns []map[string]any) {
		body, _ := json.Marshal(conns)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/agents/connections",
			bytes.NewBuffer(body)))
	}

	post([]map[string]any{
		{"agent_id": agentID, "protocol": "tcp", "local_address": "127.0.0.1:1000",
			"remote_address": "1.2.3.4:80", "state": "ESTABLISHED", "process_name": "old_proc"},
		{"agent_id": agentID, "protocol": "tcp", "local_address": "127.0.0.1:1001",
			"remote_address": "1.2.3.5:80", "state": "ESTABLISHED", "process_name": "old_proc2"},
	})
	post([]map[string]any{
		{"agent_id": agentID, "protocol": "tcp", "local_address": "127.0.0.1:2000",
			"remote_address": "9.8.7.6:443", "state": "CLOSE_WAIT", "process_name": "new_proc"},
	})

	conns, _ := repositories.GetConnectionsByAgent(fmt.Sprintf("%d", agentID))
	if len(conns) != 1 {
		t.Errorf("connection count = %d, want 1 after replace", len(conns))
	}
	if len(conns) > 0 && conns[0].ProcessName != "new_proc" {
		t.Errorf("process_name = %q, want new_proc", conns[0].ProcessName)
	}
}

// TestReceiveConnections_BadJSON verifies 400 on malformed payload.
func TestReceiveConnections_BadJSON(t *testing.T) {
	setupIntegration(t)

	r := gin.New()
	r.Use(injectClaims(1, 1, "admin"))
	r.POST("/api/agents/connections", ReceiveConnections)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/agents/connections",
		bytes.NewBufferString(`{"broken":`)))

	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON: status = %d, want 400", w.Code)
	}
}

// TestReceiveConnections_NoProcessName verifies that connections from older
// agent versions (no process fields) still store correctly with empty strings.
func TestReceiveConnections_NoProcessName(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)

	r := gin.New()
	r.Use(injectClaims(1, 1, "admin"))
	r.POST("/api/agents/connections", ReceiveConnections)

	payload := []map[string]any{
		{"agent_id": agentID, "protocol": "udp",
			"local_address": "0.0.0.0:53", "remote_address": "", "state": ""},
	}
	body, _ := json.Marshal(payload)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/agents/connections", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("no-process connections: status = %d; body: %s", w.Code, w.Body.String())
	}

	conns, _ := repositories.GetConnectionsByAgent(fmt.Sprintf("%d", agentID))
	if len(conns) == 0 {
		t.Fatal("expected 1 connection stored")
	}
	if conns[0].ProcessName != "" {
		t.Errorf("process_name = %q, want empty for legacy payload", conns[0].ProcessName)
	}
	if conns[0].PID != nil {
		t.Errorf("pid = %v, want nil for legacy payload", conns[0].PID)
	}
}
