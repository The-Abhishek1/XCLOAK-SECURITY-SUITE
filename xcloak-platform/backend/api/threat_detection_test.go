//go:build integration

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
)

func threatRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "analyst"))
	r.GET("/api/threat/scores", GetAnomalyScores)
	r.GET("/api/threat/fleet", GetFleetAnomalySummary)
	r.GET("/api/threat/baselines", GetAgentBaselines)
	r.POST("/api/threat/score/:agent_id", ScoreAgentNow)
	r.POST("/api/threat/findings/:id/acknowledge", AcknowledgeAnomalyFinding)
	return r
}

func insertTestFinding(t *testing.T, agentID, tenantID int) int {
	t.Helper()
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO anomaly_findings
		  (agent_id, tenant_id, finding_type, description, severity, score, acknowledged, source)
		VALUES ($1, $2, 'behavioral', 'Integration test finding', 'medium', 55, false, 'ai')
		RETURNING id
	`, agentID, tenantID).Scan(&id)
	if err != nil {
		t.Fatalf("insertTestFinding: %v", err)
	}
	t.Cleanup(func() {
		database.DB.Exec(`DELETE FROM anomaly_findings WHERE id = $1`, id)
	})
	return id
}

// TestGetAnomalyScores_ReturnsArray verifies the endpoint returns an array
// (not null) even when no scores exist for the tenant.
func TestGetAnomalyScores_ReturnsArray(t *testing.T) {
	setupIntegration(t)

	r := threatRouter(999)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/threat/scores", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetAnomalyScores: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp == nil {
		t.Error("response must be an array, not null")
	}
}

// TestGetFleetAnomalySummary_ReturnsArray verifies the endpoint returns an
// array even when no scores have been recorded for the tenant.
func TestGetFleetAnomalySummary_ReturnsArray(t *testing.T) {
	setupIntegration(t)

	r := threatRouter(999)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/threat/fleet", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetFleetAnomalySummary: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp == nil {
		t.Error("response must be an array, not null")
	}
}

// TestAcknowledgeAnomalyFinding_Valid verifies that acknowledging an existing
// finding returns 200.
func TestAcknowledgeAnomalyFinding_Valid(t *testing.T) {
	setupIntegration(t)

	agentID := insertTestAgent(t)
	findingID := insertTestFinding(t, agentID, 1)

	r := threatRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/threat/findings/%d/acknowledge", findingID), nil))

	if w.Code != http.StatusOK {
		t.Fatalf("AcknowledgeAnomalyFinding: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// TestAcknowledgeAnomalyFinding_CrossTenant verifies that a tenant cannot
// acknowledge another tenant's finding — must return 404.
func TestAcknowledgeAnomalyFinding_CrossTenant(t *testing.T) {
	setupIntegration(t)

	agentID := insertTestAgent(t)
	findingID := insertTestFinding(t, agentID, 1) // created under tenant 1

	r2 := threatRouter(2) // request from tenant 2
	w := httptest.NewRecorder()
	r2.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/threat/findings/%d/acknowledge", findingID), nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("cross-tenant ack: status = %d, want 404", w.Code)
	}
}

// TestGetAgentBaselines_Valid verifies that baselines can be fetched without
// error for an agent (empty array is fine — baselines build over time).
func TestGetAgentBaselines_Valid(t *testing.T) {
	setupIntegration(t)

	agentID := insertTestAgent(t)
	r := threatRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/threat/baselines?agent_id=%d", agentID), nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetAgentBaselines: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp == nil {
		t.Error("baselines response must be an array, not null")
	}
}
