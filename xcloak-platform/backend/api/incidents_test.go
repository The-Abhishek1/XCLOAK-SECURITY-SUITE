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
)

func incidentRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "analyst"))
	r.GET("/api/incidents", GetIncidents)
	r.GET("/api/incidents/counts", GetIncidentStatusCounts)
	r.GET("/api/incidents/:id/alerts", GetIncidentAlerts)
	r.PUT("/api/incidents/:id/status", UpdateIncidentStatus)
	r.PATCH("/api/incidents/:id/severity", UpdateIncidentSeverity)
	r.POST("/api/incidents/:id/notes", AddIncidentNote)
	return r
}

func insertTestIncident(t *testing.T, agentID, tenantID int) int {
	t.Helper()
	var id int
	fp := fmt.Sprintf("test-fp-%d", agentID)
	err := database.DB.QueryRow(`
		INSERT INTO incidents (agent_id, title, severity, status, description, fingerprint, tenant_id)
		VALUES ($1, 'Test Incident', 'high', 'open', 'Integration test incident', $2, $3)
		RETURNING id
	`, agentID, fp, tenantID).Scan(&id)
	if err != nil {
		t.Fatalf("insertTestIncident: %v", err)
	}
	t.Cleanup(func() {
		database.DB.Exec(`DELETE FROM incidents WHERE id = $1`, id)
	})
	return id
}

// TestGetIncidentStatusCounts verifies the counts endpoint returns a map with
// all four status keys, avoiding the O(N) getAll() pattern for tab badges.
func TestGetIncidentStatusCounts(t *testing.T) {
	setupIntegration(t)

	agentID := insertTestAgent(t)
	incID := insertTestIncident(t, agentID, 1)
	_ = incID

	r := incidentRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/incidents/counts", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetIncidentStatusCounts: status = %d; body: %s", w.Code, w.Body.String())
	}

	var counts map[string]int
	json.NewDecoder(w.Body).Decode(&counts)

	for _, status := range []string{"open", "investigating", "resolved", "closed"} {
		if _, ok := counts[status]; !ok {
			t.Errorf("counts response missing key %q", status)
		}
	}
	if counts["open"] < 1 {
		t.Errorf("open count = %d, want >= 1 (test incident is open)", counts["open"])
	}
}

// TestGetIncidentAlerts_Empty verifies that a new incident with no linked alerts
// returns an empty array (not null or 404).
func TestGetIncidentAlerts_Empty(t *testing.T) {
	setupIntegration(t)

	agentID := insertTestAgent(t)
	incID := insertTestIncident(t, agentID, 1)

	r := incidentRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/incidents/%d/alerts", incID), nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetIncidentAlerts empty: status = %d; body: %s", w.Code, w.Body.String())
	}

	var alerts []any
	json.NewDecoder(w.Body).Decode(&alerts)
	if alerts == nil {
		t.Error("linked alerts response must be an array, not null")
	}
}

// TestGetIncidentAlerts_TenantIsolation verifies that fetching alerts for an
// incident from the wrong tenant returns 404 rather than leaking the data.
func TestGetIncidentAlerts_TenantIsolation(t *testing.T) {
	setupIntegration(t)

	agentID := insertTestAgent(t)
	incID := insertTestIncident(t, agentID, 1) // created under tenant 1

	r2 := incidentRouter(2) // request from tenant 2
	w := httptest.NewRecorder()
	r2.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/incidents/%d/alerts", incID), nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("cross-tenant incident alerts: status = %d, want 404", w.Code)
	}
}

// TestUpdateIncidentSeverity_Valid verifies that a valid severity patch returns
// 200 and echoes the new severity.
func TestUpdateIncidentSeverity_Valid(t *testing.T) {
	setupIntegration(t)

	agentID := insertTestAgent(t)
	incID := insertTestIncident(t, agentID, 1)

	body, _ := json.Marshal(map[string]string{"severity": "critical"})
	r := incidentRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPatch,
		fmt.Sprintf("/api/incidents/%d/severity", incID), bytes.NewBuffer(body)))

	if w.Code != http.StatusOK {
		t.Fatalf("UpdateIncidentSeverity valid: status = %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["severity"] != "critical" {
		t.Errorf("severity = %q, want critical", resp["severity"])
	}
}

// TestUpdateIncidentSeverity_InvalidValue verifies that an unknown severity
// string returns 400.
func TestUpdateIncidentSeverity_InvalidValue(t *testing.T) {
	setupIntegration(t)

	agentID := insertTestAgent(t)
	incID := insertTestIncident(t, agentID, 1)

	body, _ := json.Marshal(map[string]string{"severity": "ultra"})
	r := incidentRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPatch,
		fmt.Sprintf("/api/incidents/%d/severity", incID), bytes.NewBuffer(body)))

	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid severity: status = %d, want 400", w.Code)
	}
}
