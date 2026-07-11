//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/services"
)

func logSearchRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "analyst"))
	r.GET("/api/logs/search", SearchLogsHandler)
	r.GET("/api/logs/searches", GetSavedLogSearches)
	r.POST("/api/logs/searches", SaveLogSearch)
	r.DELETE("/api/logs/searches/:id", DeleteSavedLogSearch)
	r.POST("/api/logs/searches/:id/run", RunSavedLogSearch)
	return r
}

// TestSearchLogs_Returns200 verifies the search endpoint is reachable with
// default params and returns a valid result body.
func TestSearchLogs_Returns200(t *testing.T) {
	setupIntegration(t)

	r := logSearchRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/logs/search?range=24h", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("SearchLogs: status = %d; body: %s", w.Code, w.Body.String())
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if _, ok := result["logs"]; !ok {
		t.Error("response missing 'logs' key")
	}
	if _, ok := result["total"]; !ok {
		t.Error("response missing 'total' key")
	}
}

// TestSearchLogs_TenantIsolation verifies that a log from tenant 2 does not
// appear in tenant 1's search results.
func TestSearchLogs_TenantIsolation(t *testing.T) {
	setupIntegration(t)

	// Insert an agent + log for tenant 2.
	unique := fmt.Sprintf("iso-log-%d", time.Now().UnixNano())
	var agent2ID int
	err := database.DB.QueryRow(`
		INSERT INTO agents (hostname, os, status, machine_id, token, tenant_id)
		VALUES ($1, 'linux', 'online', $2, $3, 2) RETURNING id
	`, unique, unique, unique).Scan(&agent2ID)
	if err != nil {
		t.Fatalf("insert tenant-2 agent: %v", err)
	}
	t.Cleanup(func() { database.DB.Exec(`DELETE FROM agents WHERE id = $1`, agent2ID) })

	logMsg := fmt.Sprintf("tenant2-secret-%d", time.Now().UnixNano())
	var logID int
	database.DB.QueryRow(`
		INSERT INTO endpoint_logs (agent_id, log_source, log_message)
		VALUES ($1, 'auth', $2) RETURNING id
	`, agent2ID, logMsg).Scan(&logID)
	t.Cleanup(func() { database.DB.Exec(`DELETE FROM endpoint_logs WHERE id = $1`, logID) })

	// Search as tenant 1 — must not see tenant-2 log.
	r := logSearchRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/logs/search?q=%s&range=24h", logMsg), nil))

	var result map[string]any
	json.NewDecoder(w.Body).Decode(&result)

	logs, _ := result["logs"].([]any)
	for _, l := range logs {
		if entry, ok := l.(map[string]any); ok {
			if entry["log_message"] == logMsg {
				t.Errorf("tenant 1 can see tenant-2 log %q — isolation breach", logMsg)
			}
		}
	}
}

// TestSaveAndRunSavedSearch_IncrementsRunCount verifies the core regression:
// running a saved search via POST /searches/:id/run must increment run_count.
// Before the fix, the frontend called /logs/search directly (bypassing /run),
// so run_count was always 0.
func TestSaveAndRunSavedSearch_IncrementsRunCount(t *testing.T) {
	setupIntegration(t)

	r := logSearchRouter(1)

	// Save a search.
	body, _ := json.Marshal(map[string]any{
		"name":       fmt.Sprintf("test-search-%d", time.Now().UnixNano()),
		"query":      "user:admin",
		"time_range": "24h",
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/logs/searches",
		bytes.NewBuffer(body)))
	if w.Code != http.StatusCreated {
		t.Fatalf("SaveLogSearch: status = %d; body: %s", w.Code, w.Body.String())
	}

	var saved map[string]any
	json.NewDecoder(w.Body).Decode(&saved)
	searchID := int(saved["id"].(float64))
	t.Cleanup(func() {
		database.DB.Exec(`DELETE FROM saved_log_searches WHERE id = $1`, searchID)
	})

	// Run it via /run.
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/logs/searches/%d/run", searchID), nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("RunSavedLogSearch: status = %d; body: %s", w2.Code, w2.Body.String())
	}

	// Verify run_count is now 1.
	var runCount int
	database.DB.QueryRow(`SELECT run_count FROM saved_log_searches WHERE id = $1`, searchID).Scan(&runCount)
	if runCount != 1 {
		t.Errorf("run_count = %d after one run, want 1", runCount)
	}
}

// TestRunSavedSearch_WrongTenant verifies that tenant 1 cannot run a saved
// search that belongs to tenant 2.
func TestRunSavedSearch_WrongTenant(t *testing.T) {
	setupIntegration(t)

	// Create a saved search for tenant 2 directly.
	unique := fmt.Sprintf("t2-search-%d", time.Now().UnixNano())
	var searchID int
	err := database.DB.QueryRow(`
		INSERT INTO saved_log_searches (name, query, time_range, created_by, tenant_id)
		VALUES ($1, 'source:syslog', '24h', 'user2', 2) RETURNING id
	`, unique).Scan(&searchID)
	if err != nil {
		t.Fatalf("insert tenant-2 saved search: %v", err)
	}
	t.Cleanup(func() { database.DB.Exec(`DELETE FROM saved_log_searches WHERE id = $1`, searchID) })

	// Try to run it as tenant 1 — must get 404.
	r := logSearchRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/logs/searches/%d/run", searchID), nil))

	if w.Code != http.StatusNotFound {
		t.Errorf("cross-tenant run: status = %d, want 404", w.Code)
	}
}

// TestGetSavedLogSearchByID_DirectQuery verifies the new direct-query function
// returns the right record and enforces tenant isolation — the old linear scan
// would find the record even if it belonged to another tenant.
func TestGetSavedLogSearchByID_DirectQuery(t *testing.T) {
	setupIntegration(t)

	unique := fmt.Sprintf("direct-%d", time.Now().UnixNano())
	var searchID int
	err := database.DB.QueryRow(`
		INSERT INTO saved_log_searches (name, query, time_range, created_by, tenant_id)
		VALUES ($1, 'test', '1h', 'tester', 1) RETURNING id
	`, unique).Scan(&searchID)
	if err != nil {
		t.Fatalf("insert saved search: %v", err)
	}
	t.Cleanup(func() { database.DB.Exec(`DELETE FROM saved_log_searches WHERE id = $1`, searchID) })

	// Correct tenant — should find it.
	idStr := fmt.Sprintf("%d", searchID)
	found, err := services.GetSavedLogSearchByID(idStr, 1)
	if err != nil {
		t.Fatalf("GetSavedLogSearchByID tenant 1: %v", err)
	}
	if found.Name != unique {
		t.Errorf("name = %q, want %q", found.Name, unique)
	}

	// Wrong tenant — must not find it.
	_, err = services.GetSavedLogSearchByID(idStr, 2)
	if err == nil {
		t.Error("GetSavedLogSearchByID(tenant=2) should return error for tenant-1 search")
	}
}
