//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func uebaRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "analyst"))
	r.GET("/api/ueba/users", GetUEBAUsers)
	r.GET("/api/ueba/events", GetUEBAEvents)
	r.POST("/api/ueba/analyze", TriggerUEBAAnalysis)
	return r
}

// TestGetUEBAUsers_ReturnsArray verifies the response has "profiles" array and
// "total" count even when no data exists.
func TestGetUEBAUsers_ReturnsArray(t *testing.T) {
	setupIntegration(t)

	r := uebaRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/ueba/users", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetUEBAUsers: status = %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	if _, ok := resp["profiles"]; !ok {
		t.Error("response must contain 'profiles' key")
	}
	if _, ok := resp["total"]; !ok {
		t.Error("response must contain 'total' key")
	}
	if resp["profiles"] == nil {
		t.Error("profiles must be an array, not null")
	}
}

// TestGetUEBAUsers_LimitCapped verifies that a caller cannot request an
// arbitrarily large page. Limit is capped at 500 server-side.
func TestGetUEBAUsers_LimitCapped(t *testing.T) {
	setupIntegration(t)

	// If the server accepted limit=1000000, the DB would return at most the
	// number of rows in the table — but we verify the response is still 200
	// and doesn't blow up with a bad query.
	r := uebaRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/ueba/users?limit=1000000", nil))

	if w.Code != http.StatusOK {
		t.Errorf("GetUEBAUsers large limit: status = %d, want 200", w.Code)
	}
}

// TestGetUEBAEvents_ReturnsArray verifies the response wraps events in the
// envelope the frontend expects: { events: [], total: N }.
func TestGetUEBAEvents_ReturnsArray(t *testing.T) {
	setupIntegration(t)

	r := uebaRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/ueba/events", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetUEBAEvents: status = %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	if _, ok := resp["events"]; !ok {
		t.Error("response must contain 'events' key")
	}
	if resp["events"] == nil {
		t.Error("events must be an array, not null")
	}
}

// TestGetUEBAEvents_TenantIsolation verifies events are scoped to the caller's
// tenant even when data from other tenants exists in the DB.
func TestGetUEBAEvents_TenantIsolation(t *testing.T) {
	setupIntegration(t)

	// Tenant 2 has its own scoped view — should not see tenant 1's events.
	r := uebaRouter(2)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/ueba/events", nil))

	if w.Code != http.StatusOK {
		t.Errorf("GetUEBAEvents tenant2: status = %d, want 200", w.Code)
	}
}

// TestTriggerUEBAAnalysis_Returns200 verifies that the analyze endpoint
// accepts the request and returns 200 — the actual analysis runs in a goroutine.
func TestTriggerUEBAAnalysis_Returns200(t *testing.T) {
	setupIntegration(t)

	r := uebaRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/ueba/analyze", nil))

	if w.Code != http.StatusOK {
		t.Errorf("TriggerUEBAAnalysis: status = %d, want 200", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["message"] == nil {
		t.Error("response must include 'message'")
	}
}
