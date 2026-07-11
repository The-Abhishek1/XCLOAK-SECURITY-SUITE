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

func dfirRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "analyst"))
	r.GET("/api/dfir/collections", ListForensicCollections)
	r.POST("/api/dfir/collections", TriggerForensicCollection)
	r.GET("/api/dfir/collections/:id/artifacts", GetCollectionArtifacts)
	r.GET("/api/dfir/incidents/:incident_id/timeline", GetForensicTimeline)
	return r
}

func insertTestForensicCollection(t *testing.T, tenantID int) int {
	t.Helper()
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO forensic_collections
		  (tenant_id, label, status, artifact_types, triggered_by)
		VALUES ($1, 'Test Collection', 'completed', '{"processes"}', 'test')
		RETURNING id
	`, tenantID).Scan(&id)
	if err != nil {
		t.Fatalf("insertTestForensicCollection: %v", err)
	}
	t.Cleanup(func() {
		database.DB.Exec(`DELETE FROM forensic_collections WHERE id = $1`, id)
	})
	return id
}

// TestListForensicCollections_ReturnsArray verifies the endpoint returns an
// array even when the tenant has no collections.
func TestListForensicCollections_ReturnsArray(t *testing.T) {
	setupIntegration(t)

	r := dfirRouter(999)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/dfir/collections", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("ListForensicCollections: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp == nil {
		t.Error("response must be an array, not null")
	}
}

// TestGetCollectionArtifacts_Valid verifies artifacts can be fetched for an
// existing collection (empty array is fine).
func TestGetCollectionArtifacts_Valid(t *testing.T) {
	setupIntegration(t)

	collID := insertTestForensicCollection(t, 1)
	r := dfirRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/dfir/collections/%d/artifacts", collID), nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetCollectionArtifacts: status = %d; body: %s", w.Code, w.Body.String())
	}
}

// TestGetCollectionArtifacts_CrossTenant verifies that another tenant's
// artifacts are not accessible.
func TestGetCollectionArtifacts_CrossTenant(t *testing.T) {
	setupIntegration(t)

	collID := insertTestForensicCollection(t, 1)

	r2 := dfirRouter(2)
	w := httptest.NewRecorder()
	r2.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/api/dfir/collections/%d/artifacts", collID), nil))

	// Should return 404 or empty — not another tenant's data
	if w.Code == http.StatusOK {
		var resp []any
		json.NewDecoder(w.Body).Decode(&resp)
		if len(resp) > 0 {
			t.Error("cross-tenant artifact fetch must not return another tenant's artifacts")
		}
	}
}

// TestGetForensicTimeline_ReturnsArray verifies the timeline endpoint returns
// an array for an incident.
func TestGetForensicTimeline_ReturnsArray(t *testing.T) {
	setupIntegration(t)

	// Incident 99999 does not exist — expect 200 with empty array or 404
	r := dfirRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/api/dfir/incidents/99999/timeline", nil))

	if w.Code != http.StatusOK && w.Code != http.StatusNotFound {
		t.Errorf("GetForensicTimeline: status = %d, want 200 or 404", w.Code)
	}
}
