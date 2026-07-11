//go:build integration

package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
	"time"
)

func networkMapRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "analyst"))
	r.GET("/api/network-map", GetNetworkMap)
	return r
}

// TestGetNetworkMap_Returns200 verifies the endpoint is reachable and returns 200.
func TestGetNetworkMap_Returns200(t *testing.T) {
	setupIntegration(t)

	r := networkMapRouter(1)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/network-map?since_minutes=60", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GetNetworkMap: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// TestGetNetworkMap_AgentAppearsAsNode verifies that an enrolled agent produces
// a node in the map graph.
func TestGetNetworkMap_AgentAppearsAsNode(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)

	graph, err := services.BuildNetworkMap(1, time.Now().Add(-time.Hour), 500)
	if err != nil {
		t.Fatalf("BuildNetworkMap: %v", err)
	}

	wantID := fmt.Sprintf("agent-%d", agentID)
	for _, n := range graph.Nodes {
		if n.ID == wantID {
			return // found
		}
	}
	t.Errorf("agent node %q not found in graph nodes", wantID)
}

// TestGetEndpointConnectionsByTenant_ReturnsProcessName verifies that the
// process_name column added in Feature 4 is returned by
// GetEndpointConnectionsByTenant and flows into ConnectEvent.Comm. Without
// this, every network-map edge sourced from endpoint_connections shows
// process="unknown" even when the agent reported a process name.
func TestGetEndpointConnectionsByTenant_ReturnsProcessName(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)

	// Insert an endpoint_connection row with process_name set.
	_, err := database.DB.Exec(`
		INSERT INTO endpoint_connections
		    (agent_id, tenant_id, protocol, local_address, remote_address,
		     state, process_name, process_path, collected_at)
		VALUES ($1, 1, 'tcp', '10.0.0.1:54321', '93.184.216.34:443',
		        'ESTABLISHED', 'curl', '/usr/bin/curl', NOW())
	`, agentID)
	if err != nil {
		t.Fatalf("insert endpoint_connection: %v", err)
	}
	t.Cleanup(func() {
		database.DB.Exec(`DELETE FROM endpoint_connections WHERE agent_id = $1`, agentID)
	})

	events, err := repositories.GetEndpointConnectionsByTenant(1, 100)
	if err != nil {
		t.Fatalf("GetEndpointConnectionsByTenant: %v", err)
	}

	for _, ev := range events {
		if ev.AgentID == agentID && ev.RemoteAddress == "93.184.216.34:443" {
			if ev.Comm != "curl" {
				t.Errorf("ConnectEvent.Comm = %q, want %q (process_name not flowing through)", ev.Comm, "curl")
			}
			return
		}
	}
	t.Error("inserted endpoint_connection not found in GetEndpointConnectionsByTenant result")
}

// TestGetNetworkMap_TenantIsolation verifies that agents from a different
// tenant are not visible in the graph.
func TestGetNetworkMap_TenantIsolation(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t) // inserted into tenant 1

	// Build map for tenant 2 — must NOT contain the agent.
	graph, err := services.BuildNetworkMap(2, time.Now().Add(-time.Hour), 500)
	if err != nil {
		t.Fatalf("BuildNetworkMap tenant 2: %v", err)
	}

	wantID := fmt.Sprintf("agent-%d", agentID)
	for _, n := range graph.Nodes {
		if n.ID == wantID {
			t.Errorf("tenant 1 agent %q leaked into tenant 2 map", wantID)
		}
	}
}
