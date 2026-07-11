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

// snoozeRouter returns a router with the three endpoints needed for snooze tests.
func snoozeRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "analyst"))
	r.PATCH("/api/alerts/:id/snooze", SnoozeAlert)
	r.GET("/api/alerts", GetAlerts)
	return r
}

// TestSnoozeAlert_HidesFromGetAlerts is the core regression test: an alert
// with suppressed_until in the future must not appear in the open-alert list.
func TestSnoozeAlert_HidesFromGetAlerts(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	alertID := insertTestAlert(t, agentID)

	r := snoozeRouter(1)

	// Snooze for 60 minutes.
	body, _ := json.Marshal(map[string]int{"minutes": 60})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/alerts/%d/snooze", alertID), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("SnoozeAlert: status = %d; body: %s", w.Code, w.Body.String())
	}

	// Alert must not appear in the repository's GetAlerts (which filters snooze).
	alerts, err := repositories.GetAlerts(1)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	for _, a := range alerts {
		if a.ID == alertID {
			t.Errorf("snoozed alert #%d still returned by GetAlerts", alertID)
		}
	}
}

// TestSnoozeAlert_SetsSuppressedUntil verifies the DB value is in the future.
func TestSnoozeAlert_SetsSuppressedUntil(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	alertID := insertTestAlert(t, agentID)

	r := snoozeRouter(1)

	body, _ := json.Marshal(map[string]int{"minutes": 240})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/alerts/%d/snooze", alertID), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("SnoozeAlert: status = %d; body: %s", w.Code, w.Body.String())
	}

	// Read back from DB and verify suppressed_until > NOW().
	var inFuture bool
	err := database.DB.QueryRow(
		`SELECT suppressed_until > NOW() FROM alerts WHERE id = $1`, alertID,
	).Scan(&inFuture)
	if err != nil {
		t.Fatalf("querying suppressed_until: %v", err)
	}
	if !inFuture {
		t.Error("suppressed_until is not in the future after snooze")
	}
}

// TestSnoozeAlert_WrongTenantReturns404 verifies that tenant isolation holds.
func TestSnoozeAlert_WrongTenantReturns404(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	alertID := insertTestAlert(t, agentID) // alert is in tenant 1

	r := snoozeRouter(2) // request from tenant 2

	body, _ := json.Marshal(map[string]int{"minutes": 60})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/alerts/%d/snooze", alertID), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("wrong-tenant snooze: status = %d, want 404", w.Code)
	}
}

// TestSnoozeAlert_InvalidMinutesReturns400 verifies duration bounds enforcement.
func TestSnoozeAlert_InvalidMinutesReturns400(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	alertID := insertTestAlert(t, agentID)

	r := snoozeRouter(1)

	for _, mins := range []int{0, -1, 99999, 20161} {
		body, _ := json.Marshal(map[string]int{"minutes": mins})
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPatch, fmt.Sprintf("/api/alerts/%d/snooze", alertID), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("minutes=%d: status = %d, want 400", mins, w.Code)
		}
	}
}

// TestSnoozeAlert_BadIDReturns400 verifies the handler rejects non-numeric IDs.
func TestSnoozeAlert_BadIDReturns400(t *testing.T) {
	setupIntegration(t)

	r := snoozeRouter(1)

	body, _ := json.Marshal(map[string]int{"minutes": 60})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/api/alerts/not-a-number/snooze", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("bad ID: status = %d, want 400", w.Code)
	}
}

// TestSnoozeAlert_ExpiredSnoozeReappears verifies that an alert with
// suppressed_until in the PAST is visible in GetAlerts again. This simulates
// a snooze window expiring by directly setting the timestamp to the past.
func TestSnoozeAlert_ExpiredSnoozeReappears(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	alertID := insertTestAlert(t, agentID)

	// Set suppressed_until to 1 hour AGO (already expired).
	database.DB.Exec(
		`UPDATE alerts SET suppressed_until = NOW() - INTERVAL '1 hour' WHERE id = $1`, alertID)

	alerts, err := repositories.GetAlerts(1)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	var found bool
	for _, a := range alerts {
		if a.ID == alertID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("alert with expired snooze (#%d) should be visible in GetAlerts", alertID)
	}
}
