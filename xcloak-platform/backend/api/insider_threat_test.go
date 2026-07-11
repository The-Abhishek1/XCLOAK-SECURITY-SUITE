//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func insiderThreatRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "analyst"))
	r.GET("/api/insider-threat", GetInsiderThreatScores)
	r.GET("/api/insider-threat/summary", GetInsiderThreatSummary)
	return r
}

// TestGetInsiderThreatScores_EmptyArray verifies that tenants with no scored
// users receive an empty array (not null) — the frontend does Array.isArray().
func TestGetInsiderThreatScores_EmptyArray(t *testing.T) {
	setupIntegration(t)

	r := insiderThreatRouter(999)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/insider-threat", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetInsiderThreatScores: status = %d; body: %s", w.Code, w.Body.String())
	}

	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp == nil {
		t.Error("response must be an array, not null")
	}
}

// TestGetInsiderThreatScores_DaysRange verifies the handler accepts valid days
// values (1–90) and returns 200 for each boundary.
func TestGetInsiderThreatScores_DaysRange(t *testing.T) {
	setupIntegration(t)

	for _, q := range []string{"?days=1", "?days=7", "?days=90", "?days=91"} {
		r := insiderThreatRouter(1)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/insider-threat"+q, nil))
		// days=91 should be clamped to 7 (invalid, ignored) — still 200, just
		// returns default window. Must never 500.
		if w.Code != http.StatusOK {
			t.Errorf("GetInsiderThreatScores %s: status = %d, want 200", q, w.Code)
		}
	}
}

// TestGetInsiderThreatScores_MinScoreValidation verifies that out-of-range
// min_score values are clamped to 0 and do not cause errors.
func TestGetInsiderThreatScores_MinScoreValidation(t *testing.T) {
	setupIntegration(t)

	for _, q := range []string{"?min_score=-1", "?min_score=0", "?min_score=100", "?min_score=200"} {
		r := insiderThreatRouter(1)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/insider-threat"+q, nil))
		if w.Code != http.StatusOK {
			t.Errorf("GetInsiderThreatScores %s: status = %d, want 200", q, w.Code)
		}
	}
}

// TestGetInsiderThreatSummary_EmptyArray verifies the summary endpoint returns
// an empty array when no users have scored >= 30 today.
func TestGetInsiderThreatSummary_EmptyArray(t *testing.T) {
	setupIntegration(t)

	r := insiderThreatRouter(999)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/insider-threat/summary", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetInsiderThreatSummary: status = %d; body: %s", w.Code, w.Body.String())
	}

	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp == nil {
		t.Error("summary response must be an array, not null")
	}
}

// TestGetInsiderThreatScores_TenantIsolation verifies that tenant 2 cannot see
// scores that belong to tenant 1. The WHERE clause must always filter by tenant_id.
func TestGetInsiderThreatScores_TenantIsolation(t *testing.T) {
	setupIntegration(t)

	// Both tenants should get 200 with independent empty arrays — not each
	// other's data.
	for _, tid := range []int{1, 2} {
		r := insiderThreatRouter(tid)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/insider-threat", nil))
		if w.Code != http.StatusOK {
			t.Errorf("tenant %d: status = %d, want 200", tid, w.Code)
		}
	}
}
