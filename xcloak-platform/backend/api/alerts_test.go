//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/repositories"
)

// insertTestAlert creates a minimal alert row in tenant 1 and registers cleanup.
func insertTestAlert(t *testing.T, agentID int) int {
	t.Helper()
	fp := fmt.Sprintf("fp-test-%d", time.Now().UnixNano())

	var id int
	err := database.DB.QueryRow(`
		INSERT INTO alerts
		  (agent_id, severity, rule_name, fingerprint, log_message, tenant_id)
		VALUES ($1, 'high', 'TestRule', $2, 'test log message', 1)
		RETURNING id
	`, agentID, fp).Scan(&id)
	if err != nil {
		t.Fatalf("insertTestAlert: %v", err)
	}
	t.Cleanup(func() {
		database.DB.Exec(`DELETE FROM alerts WHERE id = $1`, id)
	})
	return id
}

// ── PATCH /api/alerts/:id/note ──────────────────────────────────────────────

func TestUpdateAlertNote_SavesNote(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	alertID := insertTestAlert(t, agentID)

	r := gin.New()
	r.Use(injectClaims(1, 1, "analyst"))
	r.PATCH("/api/alerts/:id/note", UpdateAlertNote)

	body, _ := json.Marshal(map[string]string{"note": "Confirmed false positive — benign cron job"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/alerts/%d/note", alertID), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("UpdateAlertNote: status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// Verify note was stored.
	var note string
	err := database.DB.QueryRow(`SELECT COALESCE(note,'') FROM alerts WHERE id = $1`, alertID).Scan(&note)
	if err != nil {
		t.Fatalf("querying note: %v", err)
	}
	if note != "Confirmed false positive — benign cron job" {
		t.Errorf("note = %q, want expected value", note)
	}
}

func TestUpdateAlertNote_EmptyNoteClears(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	alertID := insertTestAlert(t, agentID)

	// Pre-set a note.
	database.DB.Exec(`UPDATE alerts SET note = 'old note' WHERE id = $1`, alertID)

	r := gin.New()
	r.Use(injectClaims(1, 1, "analyst"))
	r.PATCH("/api/alerts/:id/note", UpdateAlertNote)

	body, _ := json.Marshal(map[string]string{"note": ""})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/alerts/%d/note", alertID), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("clear note: status = %d; body: %s", w.Code, w.Body.String())
	}

	var note string
	database.DB.QueryRow(`SELECT COALESCE(note,'') FROM alerts WHERE id = $1`, alertID).Scan(&note)
	if note != "" {
		t.Errorf("note = %q after clear, want empty string", note)
	}
}

func TestUpdateAlertNote_WrongTenantReturns404(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	alertID := insertTestAlert(t, agentID) // alert is in tenant 1

	r := gin.New()
	r.Use(injectClaims(2, 1, "analyst")) // request comes from tenant 2
	r.PATCH("/api/alerts/:id/note", UpdateAlertNote)

	body, _ := json.Marshal(map[string]string{"note": "should not land"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/alerts/%d/note", alertID), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("wrong-tenant note: status = %d, want 404", w.Code)
	}
}

func TestUpdateAlertNote_BadIDReturns400(t *testing.T) {
	setupIntegration(t)

	r := gin.New()
	r.Use(injectClaims(1, 1, "analyst"))
	r.PATCH("/api/alerts/:id/note", UpdateAlertNote)

	body, _ := json.Marshal(map[string]string{"note": "test"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/alerts/not-a-number/note", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("bad ID: status = %d, want 400", w.Code)
	}
}

// ── GetAlerts — status filter ──────────────────────────────────────────────

func TestGetAlerts_OnlyReturnsOpenByDefault(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	openID := insertTestAlert(t, agentID)
	resolvedID := insertTestAlert(t, agentID)

	// Mark one as resolved.
	database.DB.Exec(`UPDATE alerts SET status = 'resolved' WHERE id = $1`, resolvedID)

	r := gin.New()
	r.Use(injectClaims(1, 1, "admin"))
	r.GET("/api/alerts", GetAlerts)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/alerts", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetAlerts: status = %d; body: %s", w.Code, w.Body.String())
	}

	var result []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode GetAlerts response: %v", err)
	}

	ids := make(map[float64]bool)
	for _, a := range result {
		if id, ok := a["id"].(float64); ok {
			ids[id] = true
		}
	}

	if !ids[float64(openID)] {
		t.Errorf("open alert #%d not in response", openID)
	}
	if ids[float64(resolvedID)] {
		t.Errorf("resolved alert #%d should not be in response", resolvedID)
	}
}

// ── Alert model roundtrip — status/note returned in response ─────────────

func TestGetAlerts_ReturnStatusAndNote(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	alertID := insertTestAlert(t, agentID)

	database.DB.Exec(`UPDATE alerts SET note = 'my note' WHERE id = $1`, alertID)

	alerts, err := repositories.GetAlerts(1)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}

	var found bool
	for _, a := range alerts {
		if a.ID == alertID {
			found = true
			if a.Status != "open" {
				t.Errorf("status = %q, want open", a.Status)
			}
			if a.Note != "my note" {
				t.Errorf("note = %q, want 'my note'", a.Note)
			}
		}
	}
	if !found {
		t.Errorf("alert #%d not found in GetAlerts result", alertID)
	}
}
