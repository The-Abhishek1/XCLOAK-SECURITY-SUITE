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

	"xcloak-platform/database"
	"xcloak-platform/repositories"
)

// ── helpers ────────────────────────────────────────────────────────────────

func clearFIMData(t *testing.T, agentID int) {
	t.Helper()
	t.Cleanup(func() {
		database.DB.Exec(`DELETE FROM fim_alerts WHERE agent_id = $1`, agentID)
		database.DB.Exec(`DELETE FROM fim_baselines WHERE agent_id = $1`, agentID)
	})
}

// ── ReceiveFIMScan ──────────────────────────────────────────────────────────

// TestFIMScan_EstablishesBaseline verifies that the first scan for an agent
// stores entries in fim_baselines (including mode/uid fields) and creates no
// alerts (there is no prior baseline to compare against).
func TestFIMScan_EstablishesBaseline(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	clearFIMData(t, agentID)

	r := gin.New()
	r.Use(injectClaims(1, 1, "admin"))
	r.POST("/api/agents/fim", ReceiveFIMScan)

	payload := map[string]any{
		"agent_id": agentID,
		"files": []map[string]any{
			{
				"file_path":   "/etc/passwd",
				"sha256_hash": "abc123",
				"file_size":   1024,
				"mode":        "-rw-r--r--",
				"uid":         0,
				"gid":         0,
			},
		},
	}
	body, _ := json.Marshal(payload)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/agents/fim", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("ReceiveFIMScan: status = %d; body: %s", w.Code, w.Body.String())
	}

	baseline, err := repositories.GetFIMBaseline(agentID)
	if err != nil {
		t.Fatalf("GetFIMBaseline: %v", err)
	}
	if len(baseline) != 1 {
		t.Fatalf("baseline entries = %d, want 1", len(baseline))
	}
	if baseline[0].FileMode != "-rw-r--r--" {
		t.Errorf("file_mode = %q, want -rw-r--r--", baseline[0].FileMode)
	}
	if baseline[0].SHA256 != "abc123" {
		t.Errorf("sha256_hash = %q, want abc123", baseline[0].SHA256)
	}

	// No alerts on first scan.
	alerts, _ := repositories.GetFIMAlerts(fmt.Sprintf("%d", agentID))
	if len(alerts) != 0 {
		t.Errorf("alerts on first scan = %d, want 0", len(alerts))
	}
}

// TestFIMScan_DetectsHashChange verifies that a second scan with a different
// hash raises a "modified" alert carrying old/new hashes.
func TestFIMScan_DetectsHashChange(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	clearFIMData(t, agentID)

	r := gin.New()
	r.Use(injectClaims(1, 1, "admin"))
	r.POST("/api/agents/fim", ReceiveFIMScan)

	scanOnce := func(hash, mode string) {
		payload := map[string]any{
			"agent_id": agentID,
			"files": []map[string]any{
				{"file_path": "/etc/passwd", "sha256_hash": hash, "file_size": 512, "mode": mode, "uid": 0},
			},
		}
		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/agents/fim",
			bytes.NewBuffer(body)))
	}

	scanOnce("hash-original", "-rw-r--r--") // establishes baseline
	scanOnce("hash-changed", "-rw-r--r--")   // triggers alert

	alerts, err := repositories.GetFIMAlerts(fmt.Sprintf("%d", agentID))
	if err != nil {
		t.Fatalf("GetFIMAlerts: %v", err)
	}
	if len(alerts) == 0 {
		t.Fatal("expected at least one FIM alert after hash change, got 0")
	}
	a := alerts[0]
	if a.ChangeType != "modified" {
		t.Errorf("change_type = %q, want modified", a.ChangeType)
	}
	if a.OldHash != "hash-original" {
		t.Errorf("old_hash = %q, want hash-original", a.OldHash)
	}
	if a.NewHash != "hash-changed" {
		t.Errorf("new_hash = %q, want hash-changed", a.NewHash)
	}
}

// TestFIMScan_DetectsPermissionChange verifies that a chmod (no hash change)
// raises a "permission_change" alert carrying old/new mode strings.
func TestFIMScan_DetectsPermissionChange(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	clearFIMData(t, agentID)

	r := gin.New()
	r.Use(injectClaims(1, 1, "admin"))
	r.POST("/api/agents/fim", ReceiveFIMScan)

	const sameHash = "hash-unchanged"

	scanOnce := func(mode string) {
		payload := map[string]any{
			"agent_id": agentID,
			"files": []map[string]any{
				{"file_path": "/usr/bin/sudo", "sha256_hash": sameHash, "file_size": 200000, "mode": mode, "uid": 0},
			},
		}
		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/agents/fim",
			bytes.NewBuffer(body)))
	}

	scanOnce("-rwxr-xr-x")  // baseline: normal sudo binary
	scanOnce("-rwsr-xr-x")  // setuid bit added — classic backdoor pattern

	alerts, err := repositories.GetFIMAlerts(fmt.Sprintf("%d", agentID))
	if err != nil {
		t.Fatalf("GetFIMAlerts: %v", err)
	}
	if len(alerts) == 0 {
		t.Fatal("expected permission_change alert after chmod, got 0")
	}
	a := alerts[0]
	if a.ChangeType != "permission_change" {
		t.Errorf("change_type = %q, want permission_change", a.ChangeType)
	}
	if a.OldMode != "-rwxr-xr-x" {
		t.Errorf("old_mode = %q, want -rwxr-xr-x", a.OldMode)
	}
	if a.NewMode != "-rwsr-xr-x" {
		t.Errorf("new_mode = %q, want -rwsr-xr-x", a.NewMode)
	}
	// Hash must stay the same — this is NOT a hash-change alert.
	if a.OldHash != sameHash || a.NewHash != sameHash {
		t.Errorf("hashes changed in permission_change alert (old=%q new=%q)", a.OldHash, a.NewHash)
	}
}

// TestFIMScan_DetectsDeletedFile verifies that a file absent from the next scan
// raises a "deleted" alert.
func TestFIMScan_DetectsDeletedFile(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	clearFIMData(t, agentID)

	r := gin.New()
	r.Use(injectClaims(1, 1, "admin"))
	r.POST("/api/agents/fim", ReceiveFIMScan)

	sendFiles := func(filePaths []string) {
		var files []map[string]any
		for _, p := range filePaths {
			files = append(files, map[string]any{
				"file_path": p, "sha256_hash": "somehash", "file_size": 100,
			})
		}
		payload := map[string]any{"agent_id": agentID, "files": files}
		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/agents/fim",
			bytes.NewBuffer(body)))
	}

	sendFiles([]string{"/etc/passwd", "/etc/hosts"}) // baseline
	sendFiles([]string{"/etc/passwd"})                // /etc/hosts missing → deleted

	alerts, _ := repositories.GetFIMAlerts(fmt.Sprintf("%d", agentID))
	var found bool
	for _, a := range alerts {
		if a.FilePath == "/etc/hosts" && a.ChangeType == "deleted" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected deleted alert for /etc/hosts, not found")
	}
}

// TestFIMScan_BadJSON verifies the handler rejects malformed input.
func TestFIMScan_BadJSON(t *testing.T) {
	setupIntegration(t)

	r := gin.New()
	r.Use(injectClaims(1, 1, "admin"))
	r.POST("/api/agents/fim", ReceiveFIMScan)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/agents/fim",
		bytes.NewBufferString("not-json{")))

	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON: status = %d, want 400", w.Code)
	}
}
