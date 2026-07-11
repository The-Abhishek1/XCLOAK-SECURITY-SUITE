//go:build integration

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

func timelineRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "analyst"))
	r.GET("/api/timeline", GetTenantTimeline)
	r.GET("/api/agents/:id/timeline", GetAgentTimeline)
	return r
}

// TestGetTenantTimeline_Returns200 verifies the tenant-wide endpoint is
// reachable and returns a JSON array.
func TestGetTenantTimeline_Returns200(t *testing.T) {
	setupIntegration(t)

	r := timelineRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/timeline", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetTenantTimeline: status = %d; body: %s", w.Code, w.Body.String())
	}

	var events []models.TimelineEvent
	if err := json.NewDecoder(w.Body).Decode(&events); err != nil {
		// Empty array decodes fine; nil body would be an error.
		if w.Body.String() != "null" {
			t.Fatalf("decode events: %v", err)
		}
	}
}

// TestGetTenantTimeline_IncludesAlertWithSeverity verifies that an alert
// created for a tenant agent appears in the timeline with its severity set.
// Before the fix, severity was always empty — the frontend color-coding was dead.
func TestGetTenantTimeline_IncludesAlertWithSeverity(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)

	// Insert a critical alert directly.
	unique := fmt.Sprintf("tl-alert-%d", time.Now().UnixNano())
	var alertID int
	err := database.DB.QueryRow(`
		INSERT INTO alerts (agent_id, tenant_id, severity, rule_name, log_message, status)
		VALUES ($1, 1, 'critical', $2, 'test', 'open')
		RETURNING id
	`, agentID, unique).Scan(&alertID)
	if err != nil {
		t.Fatalf("insert alert: %v", err)
	}
	t.Cleanup(func() { database.DB.Exec(`DELETE FROM alerts WHERE id = $1`, alertID) })

	r := timelineRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/timeline", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetTenantTimeline: %d; %s", w.Code, w.Body.String())
	}

	var events []map[string]any
	json.NewDecoder(w.Body).Decode(&events)

	found := false
	for _, e := range events {
		if e["message"] == unique {
			found = true
			if e["severity"] != "critical" {
				t.Errorf("severity = %v, want critical", e["severity"])
			}
			if e["event_type"] != "alert" {
				t.Errorf("event_type = %v, want alert", e["event_type"])
			}
			break
		}
	}
	if !found {
		t.Error("inserted alert not found in tenant timeline")
	}
}

// TestGetTenantTimeline_TenantIsolation verifies that tenant 1 cannot see
// timeline events belonging to tenant 2.
func TestGetTenantTimeline_TenantIsolation(t *testing.T) {
	setupIntegration(t)

	// Agent in tenant 2
	unique := fmt.Sprintf("iso-tl-%d", time.Now().UnixNano())
	var agentID2 int
	err := database.DB.QueryRow(`
		INSERT INTO agents (hostname, os, status, machine_id, token, tenant_id)
		VALUES ($1, 'linux', 'online', $2, $3, 2)
		RETURNING id
	`, unique, unique, unique).Scan(&agentID2)
	if err != nil {
		t.Fatalf("insert tenant-2 agent: %v", err)
	}
	t.Cleanup(func() { database.DB.Exec(`DELETE FROM agents WHERE id = $1`, agentID2) })

	alertMsg := fmt.Sprintf("tenant2-alert-%d", time.Now().UnixNano())
	var alertID int
	database.DB.QueryRow(`
		INSERT INTO alerts (agent_id, tenant_id, severity, rule_name, log_message, status)
		VALUES ($1, 2, 'high', $2, 'test', 'open')
		RETURNING id
	`, agentID2, alertMsg).Scan(&alertID)
	t.Cleanup(func() { database.DB.Exec(`DELETE FROM alerts WHERE id = $1`, alertID) })

	// Query as tenant 1 — must not see tenant 2's alert.
	r := timelineRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/timeline", nil))

	var events []map[string]any
	json.NewDecoder(w.Body).Decode(&events)

	for _, e := range events {
		if e["message"] == alertMsg {
			t.Errorf("tenant 1 can see tenant-2 timeline event %q — isolation breach", alertMsg)
		}
	}
}

// TestGetAgentTimeline_Returns200 verifies the per-agent endpoint returns 200.
func TestGetAgentTimeline_Returns200(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)

	r := timelineRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/agents/%d/timeline", agentID), nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetAgentTimeline: status = %d; body: %s", w.Code, w.Body.String())
	}
}
