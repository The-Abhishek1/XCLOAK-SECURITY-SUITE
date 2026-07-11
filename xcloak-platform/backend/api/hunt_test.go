//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
)

func huntRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "analyst"))
	r.GET("/api/hunt/queries", GetHuntQueries)
	r.POST("/api/hunt/run", RunHunt)
	r.POST("/api/hunt/queries/:id/run", RerunHuntQuery)
	r.DELETE("/api/hunt/queries/:id", DeleteHuntQuery)
	r.POST("/api/sigma/rules/from-hunt", PromoteHuntToSigmaRule)
	return r
}

func insertTestHuntQuery(t *testing.T, tenantID int) int {
	t.Helper()
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO hunt_queries
		  (tenant_id, name, query_type, query_text, created_by)
		VALUES ($1, 'Test Hunt', 'process', 'nmap', 'test')
		RETURNING id
	`, tenantID).Scan(&id)
	if err != nil {
		t.Fatalf("insertTestHuntQuery: %v", err)
	}
	t.Cleanup(func() {
		database.DB.Exec(`DELETE FROM hunt_queries WHERE id = $1`, id)
	})
	return id
}

// TestGetHuntQueries_ReturnsArray verifies the endpoint returns an array.
func TestGetHuntQueries_ReturnsArray(t *testing.T) {
	setupIntegration(t)

	r := huntRouter(999)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/hunt/queries", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("GetHuntQueries: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp == nil {
		t.Error("response must be an array, not null")
	}
}

// TestDeleteHuntQuery_CrossTenant verifies that a tenant cannot delete
// another tenant's saved hunt query.
func TestDeleteHuntQuery_CrossTenant(t *testing.T) {
	setupIntegration(t)

	queryID := insertTestHuntQuery(t, 1)

	r2 := huntRouter(2)
	w := httptest.NewRecorder()
	r2.ServeHTTP(w, httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/api/hunt/queries/%d", queryID), nil))

	// Verify the query still exists under tenant 1
	var count int
	database.DB.QueryRow(`SELECT COUNT(*) FROM hunt_queries WHERE id=$1 AND tenant_id=1`, queryID).Scan(&count)
	if count != 1 {
		t.Error("cross-tenant delete must not remove the original query")
	}
}

// TestPromoteHuntToSigmaRule_Valid verifies that a hunt query can be promoted
// to a Sigma rule.
func TestPromoteHuntToSigmaRule_Valid(t *testing.T) {
	setupIntegration(t)

	body, _ := json.Marshal(map[string]any{
		"name":       "Nmap Detection",
		"query_type": "process",
		"query_text": "nmap",
	})
	r := huntRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		"/api/sigma/rules/from-hunt", bytes.NewReader(body)))

	if w.Code != http.StatusCreated {
		t.Fatalf("PromoteHuntToSigmaRule: status = %d; body: %s", w.Code, w.Body.String())
	}
	// Cleanup promoted rule
	database.DB.Exec(`DELETE FROM sigma_rules WHERE title='Nmap Detection' AND tenant_id=1`)
}

// TestPromoteHuntToSigmaRule_MissingQueryText verifies validation.
func TestPromoteHuntToSigmaRule_MissingQueryText(t *testing.T) {
	setupIntegration(t)

	body, _ := json.Marshal(map[string]any{
		"name": "Missing query text",
	})
	r := huntRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		"/api/sigma/rules/from-hunt", bytes.NewReader(body)))

	if w.Code != http.StatusBadRequest {
		t.Errorf("missing query_text: status = %d, want 400", w.Code)
	}
}
