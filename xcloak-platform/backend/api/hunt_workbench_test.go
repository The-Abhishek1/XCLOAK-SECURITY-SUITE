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

func huntWorkbenchRouter(tenantID int) *gin.Engine {
	r := gin.New()
	r.Use(injectClaims(tenantID, 1, "analyst"))
	r.GET("/api/hunt/templates", ListHuntTemplates)
	r.POST("/api/hunt/templates", CreateHuntTemplate)
	r.DELETE("/api/hunt/templates/:id", DeleteHuntTemplate)
	r.GET("/api/hunt/runs", ListHuntRuns)
	r.GET("/api/hunt/runs/:id", GetHuntRunDetail)
	r.POST("/api/hunt/execute", ExecuteHunt)
	r.PATCH("/api/hunt/runs/:id/notes", UpdateHuntRunNotes)
	return r
}

func insertTestHuntTemplate(t *testing.T, tenantID int) int {
	t.Helper()
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO hunt_templates
		  (tenant_id, name, query_type, query_text, description, tags, created_by)
		VALUES ($1, 'Test Template', 'process', 'nmap', 'desc', '{}', 'test')
		RETURNING id
	`, tenantID).Scan(&id)
	if err != nil {
		t.Fatalf("insertTestHuntTemplate: %v", err)
	}
	t.Cleanup(func() {
		database.DB.Exec(`DELETE FROM hunt_templates WHERE id = $1`, id)
	})
	return id
}

// TestListHuntTemplates_ReturnsArray verifies templates endpoint returns array.
func TestListHuntTemplates_ReturnsArray(t *testing.T) {
	setupIntegration(t)

	r := huntWorkbenchRouter(999)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/hunt/templates", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("ListHuntTemplates: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp == nil {
		t.Error("templates response must be an array, not null")
	}
}

// TestCreateHuntTemplate_Valid verifies a template can be created.
func TestCreateHuntTemplate_Valid(t *testing.T) {
	setupIntegration(t)

	body, _ := json.Marshal(map[string]any{
		"name":        "Nmap Scanner Template",
		"query_type":  "process",
		"query_text":  "nmap",
		"description": "detect nmap scans",
	})
	r := huntWorkbenchRouter(1)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/hunt/templates",
		bytes.NewReader(body)))

	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("CreateHuntTemplate: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["id"] == nil {
		t.Error("response must include id")
	}
	if id, ok := resp["id"].(float64); ok {
		database.DB.Exec(`DELETE FROM hunt_templates WHERE id = $1`, int(id))
	}
}

// TestDeleteHuntTemplate_CrossTenant verifies tenant isolation on delete.
func TestDeleteHuntTemplate_CrossTenant(t *testing.T) {
	setupIntegration(t)

	tmplID := insertTestHuntTemplate(t, 1)

	r2 := huntWorkbenchRouter(2)
	w := httptest.NewRecorder()
	r2.ServeHTTP(w, httptest.NewRequest(http.MethodDelete,
		fmt.Sprintf("/api/hunt/templates/%d", tmplID), nil))

	var count int
	database.DB.QueryRow(`SELECT COUNT(*) FROM hunt_templates WHERE id=$1 AND tenant_id=1`, tmplID).Scan(&count)
	if count != 1 {
		t.Error("cross-tenant delete must not remove another tenant's hunt template")
	}
}

// TestListHuntRuns_ReturnsArray verifies hunt runs endpoint returns array.
func TestListHuntRuns_ReturnsArray(t *testing.T) {
	setupIntegration(t)

	r := huntWorkbenchRouter(999)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/hunt/runs", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("ListHuntRuns: status = %d; body: %s", w.Code, w.Body.String())
	}
	var resp []any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp == nil {
		t.Error("hunt runs response must be an array, not null")
	}
}
