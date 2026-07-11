//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/services"
)

func riskPostureRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "analyst"))
	r.GET("/api/risk-posture", GetRiskPosture)
	r.POST("/api/risk-posture/refresh", RefreshRiskPosture)
	r.GET("/api/risk-posture/history", GetRiskPostureHistoryHandler)
	return r
}

// TestGetRiskPosture_Returns200 verifies the endpoint is reachable and returns
// a valid snapshot body.
func TestGetRiskPosture_Returns200(t *testing.T) {
	setupIntegration(t)

	r := riskPostureRouter(1)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/risk-posture", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GetRiskPosture: status = %d; body: %s", w.Code, w.Body.String())
	}

	var snap models.RiskPostureSnapshot
	if err := json.NewDecoder(w.Body).Decode(&snap); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if snap.Score < 0 || snap.Score > 100 {
		t.Errorf("score = %d, want 0-100", snap.Score)
	}
}

// TestComputeRiskPosture_SnoozedAlertsNotCounted is the core regression test:
// a snoozed alert must NOT contribute to the alert score, because we already
// fixed the snooze filter in the alert-score query. Without the filter,
// snoozing an alert on the alerts page had no effect on the risk posture.
func TestComputeRiskPosture_SnoozedAlertsNotCounted(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	alertID := insertTestAlert(t, agentID)

	// Compute score baseline with the alert open (not snoozed).
	snapBefore, err := services.ComputeRiskPosture(1)
	if err != nil {
		t.Fatalf("ComputeRiskPosture before: %v", err)
	}

	// Snooze the alert for 60 minutes.
	database.DB.Exec(`
		UPDATE alerts SET suppressed_until = NOW() + INTERVAL '60 minutes',
		                  severity = 'critical'
		WHERE id = $1`, alertID)

	// Compute again — alert score must be lower or equal now that the
	// critical alert is snoozed.
	snapAfter, err := services.ComputeRiskPosture(1)
	if err != nil {
		t.Fatalf("ComputeRiskPosture after snooze: %v", err)
	}

	if snapAfter.AlertScore > snapBefore.AlertScore {
		t.Errorf("alert_score increased after snooze (%d → %d); snoozed alerts should be excluded",
			snapBefore.AlertScore, snapAfter.AlertScore)
	}
}

// TestComputeRiskPosture_SnoozedAlertCountReported verifies that the
// snoozed_alert_count field in the response accurately reports how many alerts
// are currently snoozed, so the frontend can explain the score to the user.
func TestComputeRiskPosture_SnoozedAlertCountReported(t *testing.T) {
	setupIntegration(t)
	agentID := insertTestAgent(t)
	alertID := insertTestAlert(t, agentID)

	// Snooze the alert.
	database.DB.Exec(`
		UPDATE alerts SET suppressed_until = NOW() + INTERVAL '60 minutes' WHERE id = $1`, alertID)

	snap, err := services.ComputeRiskPosture(1)
	if err != nil {
		t.Fatalf("ComputeRiskPosture: %v", err)
	}

	if snap.SnoozedAlertCount < 1 {
		t.Errorf("snoozed_alert_count = %d, want >= 1 after snoozing an alert", snap.SnoozedAlertCount)
	}
}

// TestGetRiskPosture_AutoRefreshesStaleSnapshot verifies that a snapshot older
// than 1 hour triggers a recomputation. Before the fix, the API returned the
// stale snapshot regardless of age.
func TestGetRiskPosture_AutoRefreshesStaleSnapshot(t *testing.T) {
	setupIntegration(t)

	// Insert a snapshot that is 2 hours old.
	var oldID int
	err := database.DB.QueryRow(`
		INSERT INTO risk_posture_snapshots
		    (tenant_id, score, vuln_score, ueba_score, alert_score, ioc_score,
		     asset_scores, snapshot_at)
		VALUES (1, 42, 10, 5, 15, 12, '[]', NOW() - INTERVAL '2 hours')
		RETURNING id
	`).Scan(&oldID)
	if err != nil {
		t.Fatalf("insert stale snapshot: %v", err)
	}
	t.Cleanup(func() {
		database.DB.Exec(`DELETE FROM risk_posture_snapshots WHERE tenant_id = 1`)
	})

	r := riskPostureRouter(1)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/risk-posture", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GetRiskPosture: status = %d; body: %s", w.Code, w.Body.String())
	}

	var snap models.RiskPostureSnapshot
	json.NewDecoder(w.Body).Decode(&snap)

	// A new snapshot must have been written (ID will be higher than the stale one).
	if snap.ID <= oldID {
		t.Errorf("returned snapshot ID %d <= stale snapshot ID %d; expected a fresh recomputation",
			snap.ID, oldID)
	}

	// The new snapshot must be recent (within the last minute).
	if time.Since(snap.SnapshotAt) > time.Minute {
		t.Errorf("refreshed snapshot is %v old, want < 1 minute", time.Since(snap.SnapshotAt))
	}
}

// TestGetRiskPostureHistory_Returns200 verifies the history endpoint.
func TestGetRiskPostureHistory_Returns200(t *testing.T) {
	setupIntegration(t)

	r := riskPostureRouter(1)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/risk-posture/history?limit=5", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("GetRiskPostureHistory: status = %d", w.Code)
	}

	var history []models.RiskPostureSnapshot
	if err := json.NewDecoder(w.Body).Decode(&history); err != nil {
		t.Fatalf("decode history: %v", err)
	}
}
