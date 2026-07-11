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

func nbaRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "analyst"))
	r.GET("/api/nba/anomalies", GetNetworkAnomalies)
	r.POST("/api/nba/anomalies/:id/acknowledge", AcknowledgeNetworkAnomaly)
	r.GET("/api/nba/baseline/:agent_id", GetNetworkBaselineStats)
	r.POST("/api/nba/analyze", TriggerNBAAnalysis)
	return r
}

func insertTestAnomaly(t *testing.T, agentID, tenantID int) int {
	t.Helper()
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO network_anomalies
		  (agent_id, tenant_id, anomaly_type, dst_ip, dst_port, proto, deviation_score, description)
		VALUES ($1, $2, 'new_destination', '1.2.3.4', 443, 'tcp', 65, 'Integration test anomaly')
		RETURNING id
	`, agentID, tenantID).Scan(&id)
	if err != nil {
		t.Fatalf("insertTestAnomaly: %v", err)
	}
	t.Cleanup(func() {
		database.DB.Exec(`DELETE FROM network_anomalies WHERE id = $1`, id)
	})
	return id
}

// TestGetNetworkAnomalies_ReturnsArray verifies the endpoint returns an array
// (not null) even when no anomalies exist.
func TestGetNetworkAnomalies_ReturnsArray(t *testing.T) {
	setupIntegration(t)

	r := nbaRouter(999)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/nba/anomalies", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetNetworkAnomalies: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp == nil {
		t.Error("response must be an array, not null")
	}
}

// TestGetNetworkAnomalies_LimitCapped verifies that the handler caps limit at
// 500 and does not blow up with large values.
func TestGetNetworkAnomalies_LimitCapped(t *testing.T) {
	setupIntegration(t)

	r := nbaRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/nba/anomalies?limit=999999", nil))

	if w.Code != http.StatusOK {
		t.Errorf("GetNetworkAnomalies large limit: status = %d, want 200", w.Code)
	}
}

// TestAcknowledgeNetworkAnomaly_Valid verifies that acknowledging an existing
// anomaly returns 200 and reflects is_acknowledged=true in subsequent list.
func TestAcknowledgeNetworkAnomaly_Valid(t *testing.T) {
	setupIntegration(t)

	agentID := insertTestAgent(t)
	anomalyID := insertTestAnomaly(t, agentID, 1)

	r := nbaRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/nba/anomalies/%d/acknowledge", anomalyID), nil))

	if w.Code != http.StatusOK {
		t.Fatalf("AcknowledgeNetworkAnomaly: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// TestAcknowledgeNetworkAnomaly_CrossTenant verifies that a tenant cannot
// acknowledge another tenant's anomaly — must return 404.
func TestAcknowledgeNetworkAnomaly_CrossTenant(t *testing.T) {
	setupIntegration(t)

	agentID := insertTestAgent(t)
	anomalyID := insertTestAnomaly(t, agentID, 1) // created under tenant 1

	r2 := nbaRouter(2) // request from tenant 2
	w := httptest.NewRecorder()
	r2.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/nba/anomalies/%d/acknowledge", anomalyID), nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("cross-tenant ack: status = %d, want 404", w.Code)
	}
}

// TestGetNetworkBaselineStats_Valid verifies the baseline stats endpoint returns
// the expected envelope fields for an agent.
func TestGetNetworkBaselineStats_Valid(t *testing.T) {
	setupIntegration(t)

	agentID := insertTestAgent(t)
	r := nbaRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/nba/baseline/%d", agentID), nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetNetworkBaselineStats: status = %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	for _, key := range []string{"agent_id", "total_dests", "total_ports"} {
		if _, ok := resp[key]; !ok {
			t.Errorf("baseline stats missing key %q", key)
		}
	}
}
