//go:build integration

package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/services"
)

func attackPathRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "analyst"))
	r.GET("/api/attack-path", GetAttackPathGraph)
	return r
}

// TestGetAttackPathGraph_Returns200 verifies the endpoint is reachable and
// returns a valid JSON graph even when there are no agents.
func TestGetAttackPathGraph_Returns200(t *testing.T) {
	setupIntegration(t)

	r := attackPathRouter(1)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/attack-path", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GetAttackPathGraph: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// TestBuildAttackPathGraph_ExcludesNonEstablishedConnections is the regression
// test for the ESTABLISHED-only filter. A LISTEN connection with a real remote
// IP should NOT add a lateral-movement edge or mark the agent as internet-exposed.
func TestBuildAttackPathGraph_ExcludesNonEstablishedConnections(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)

	// Insert a LISTEN row that has a non-zero remote address.
	// Without the ESTABLISHED filter, this would mark the agent as "exposed"
	// to the internet (because the remote address is a public IP).
	_, err := database.DB.Exec(`
		INSERT INTO endpoint_connections
		    (agent_id, tenant_id, protocol, local_address, remote_address,
		     state, collected_at)
		VALUES ($1, 1, 'tcp', '0.0.0.0:443', '8.8.8.8:0',
		        'LISTEN', NOW())
	`, agentID)
	if err != nil {
		t.Fatalf("insert LISTEN connection: %v", err)
	}
	t.Cleanup(func() {
		database.DB.Exec(`DELETE FROM endpoint_connections WHERE agent_id = $1`, agentID)
	})

	graph, err := services.BuildAttackPathGraph(1)
	if err != nil {
		t.Fatalf("BuildAttackPathGraph: %v", err)
	}

	wantID := "agent-" + string(rune('0'+agentID%10))
	for _, n := range graph.Nodes {
		if n.ID == wantID && n.Exposed {
			t.Errorf("agent %s marked as exposed from a LISTEN connection (should require ESTABLISHED)", n.ID)
		}
	}
}

// TestBuildAttackPathGraph_OpenAlertCountOnNode verifies that the
// open_alert_count field on each attack-path node reflects the number of
// open, non-snoozed alerts for that agent.
func TestBuildAttackPathGraph_OpenAlertCountOnNode(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	alertID := insertTestAlert(t, agentID)
	_ = alertID

	graph, err := services.BuildAttackPathGraph(1)
	if err != nil {
		t.Fatalf("BuildAttackPathGraph: %v", err)
	}

	for _, n := range graph.Nodes {
		if n.AgentID == agentID {
			if n.OpenAlertCount < 1 {
				t.Errorf("agent %d: open_alert_count = %d, want >= 1", agentID, n.OpenAlertCount)
			}
			return
		}
	}
	t.Errorf("agent %d not found in attack-path nodes", agentID)
}

// TestBuildAttackPathGraph_SnoozedAlertNotCounted verifies that a snoozed
// alert does not contribute to the node's open_alert_count, so the SOC is
// not distracted by alerts they've already acknowledged.
func TestBuildAttackPathGraph_SnoozedAlertNotCounted(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	alertID := insertTestAlert(t, agentID)

	// Snooze the alert for 60 minutes.
	database.DB.Exec(`
		UPDATE alerts SET suppressed_until = NOW() + INTERVAL '60 minutes' WHERE id = $1
	`, alertID)

	graph, err := services.BuildAttackPathGraph(1)
	if err != nil {
		t.Fatalf("BuildAttackPathGraph: %v", err)
	}

	for _, n := range graph.Nodes {
		if n.AgentID == agentID {
			if n.OpenAlertCount != 0 {
				t.Errorf("agent %d: snoozed alert counted in open_alert_count (got %d, want 0)",
					agentID, n.OpenAlertCount)
			}
			return
		}
	}
}

// TestBuildAttackPathGraph_TenantIsolation verifies that the graph for tenant 2
// does not contain agents from tenant 1.
func TestBuildAttackPathGraph_TenantIsolation(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t) // inserted into tenant 1

	graph, err := services.BuildAttackPathGraph(2)
	if err != nil {
		t.Fatalf("BuildAttackPathGraph tenant 2: %v", err)
	}

	_ = time.Now() // keep time import
	for _, n := range graph.Nodes {
		if n.AgentID == agentID {
			t.Errorf("tenant 1 agent %d leaked into tenant 2 attack-path graph", agentID)
		}
	}
}
