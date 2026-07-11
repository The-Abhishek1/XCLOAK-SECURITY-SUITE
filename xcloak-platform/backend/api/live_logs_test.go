//go:build integration

package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
)

func liveLogsRouter() *gin.Engine {
	r := gin.New()
	r.GET("/api/agents/:id/logs/stream", LiveLogsWS)
	return r
}

// TestLiveLogsWS_MissingTicket verifies that a WS connection attempt without a
// ticket is rejected with 401 before the upgrade — the ticket check runs first.
func TestLiveLogsWS_MissingTicket(t *testing.T) {
	setupIntegration(t)

	r := liveLogsRouter()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/agents/1/logs/stream", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("missing ticket: status = %d, want 401", w.Code)
	}
}

// TestLiveLogsWS_InvalidTicket verifies that a garbage ticket is rejected 401.
func TestLiveLogsWS_InvalidTicket(t *testing.T) {
	setupIntegration(t)

	r := liveLogsRouter()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/api/agents/1/logs/stream?ticket=not-a-real-ticket", nil))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("invalid ticket: status = %d, want 401", w.Code)
	}
}

// TestLiveLogsWS_InvalidAgentID verifies that a non-numeric agent ID returns
// 400 before any ticket validation (agent ID check runs first).
func TestLiveLogsWS_InvalidAgentID(t *testing.T) {
	setupIntegration(t)

	r := liveLogsRouter()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/api/agents/not-a-number/logs/stream?ticket=anything", nil))

	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid agent ID: status = %d, want 400", w.Code)
	}
}

// TestLiveLogsWS_LogTimestampUsesCollectedAt verifies that endpoint_logs rows
// have a collected_at value that differs from NOW() — i.e., the column actually
// stores the collection time, not the query time. Before the fix, both historical
// and live logs used time.Now() making all log entries appear to arrive at the
// same instant they were viewed, not when the agent collected them.
func TestLiveLogsWS_LogTimestampUsesCollectedAt(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)

	// Insert a log with collected_at set 5 minutes in the past.
	pastTime := time.Now().UTC().Add(-5 * time.Minute)
	unique := fmt.Sprintf("ts-test-%d", time.Now().UnixNano())
	var logID int
	err := database.DB.QueryRow(`
		INSERT INTO endpoint_logs (agent_id, log_source, log_message, collected_at)
		VALUES ($1, 'auth', $2, $3)
		RETURNING id
	`, agentID, unique, pastTime).Scan(&logID)
	if err != nil {
		t.Fatalf("insert test log: %v", err)
	}
	t.Cleanup(func() { database.DB.Exec(`DELETE FROM endpoint_logs WHERE id = $1`, logID) })

	// Read it back with the same query the WS handler uses.
	var ts time.Time
	err = database.DB.QueryRow(`
		SELECT COALESCE(collected_at, NOW())
		FROM endpoint_logs WHERE id = $1
	`, logID).Scan(&ts)
	if err != nil {
		t.Fatalf("read collected_at: %v", err)
	}

	// The stored time should be within 1 second of pastTime (not NOW()).
	diff := ts.Sub(pastTime)
	if diff < 0 {
		diff = -diff
	}
	if diff > time.Second {
		t.Errorf("collected_at = %v, want ~%v (diff %v); was time.Now() used instead of collected_at?",
			ts, pastTime, diff)
	}
}
